#!/bin/bash
# run.sh - A0 (issue #5): are the protocol/attribute ids baked into compiled
# rules stable across mmt-dpi versions?
#
# For each mmt-dpi ref it builds mmt-dpi from source in a fresh ubuntu
# container, then encodes every rules/*.xml of this repository's HEAD commit
# (`git archive HEAD`, not the working tree) with compile_rule -c twice (with the
# committed src/dpi/mmt_dpi.h, and with a header regenerated from that DPI),
# and resolves the same (proto, att) pairs with that libmmt_core at run time.
# compare.py then prints the ids per version and every difference.
#
# Usage: tools/dpi-id-stability/run.sh [-w WORKDIR] [-i IMAGE] [-j PARALLEL] [REF...]
#   REF       [LABEL=]COMMIT: an mmt-dpi commit (or tag), shown as LABEL
#             (default: the A0 set below, pinned to full commits)
#   WORKDIR   scratch directory (default: tools/dpi-id-stability/.work, gitignored;
#             about 200 MB after a run, remove it with rm -rf)
#   IMAGE     base image (default: ubuntu:24.04, pinned by digest below)
#   PARALLEL  containers at once (default: 3)
#
# Uncommitted changes are not measured: commit them first. The tool warns when
# rules/ or src/ differ from HEAD.
#
# Needs docker (user in the docker group) and git; no sudo. Containers run as
# root inside (to install mmt-dpi under /opt/mmt) and chown their output back
# to the caller. Nothing is written outside WORKDIR.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$HERE/.work
# ubuntu:24.04 as of 2026-11-20 (multi-arch index digest)
IMAGE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
PARALLEL=3
DPI_URL=https://github.com/Montimage/mmt-dpi.git

while getopts "w:i:j:h" o; do
	case $o in
	w) WORK=$OPTARG ;;
	i) IMAGE=$OPTARG ;;
	j) PARALLEL=$OPTARG ;;
	*) sed -n '2,27p' "$0"; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

# fd93012d: the DPI the committed src/dpi/mmt_dpi.h was generated from
#           (its first line says "MMT-DPI v1.7.10 (fd93012d)")
# 6b1c9f53: the old upstream CI pin (.github/workflows/c-cpp.yml)
# v1.8.0:   the only 1.8.x tag
# Tags are pinned to the commits they named on 2026-11-20; a moved tag is reported.
REFS=("$@")
[ ${#REFS[@]} -gt 0 ] || REFS=(
	fd93012d=fd93012d5f92e09226a7194b6b8c110b35bb011e
	6b1c9f53=6b1c9f5380a4db616c90bec3cfeda72bce5920a0
	v1.8.0=af4c3cd7c4d04307411ef17bb16971a0df47f3d1
	v1.10.2=a84a6050963c0933d948f07576dc11c6626b5b1d
	v1.10.3=6a0afb468cdb6e5d31012de54e7f751f2f337696
)
label_of(){ local l=${1%%=*}; echo "${l//\//_}"; }
commit_of(){ echo "${1#*=}"; }

mkdir -p "$WORK/out"
WORK=$(cd "$WORK" && pwd)

if [ -d "$WORK/mmt-dpi-src/.git" ]; then
	git -C "$WORK/mmt-dpi-src" fetch -q --tags origin
else
	git clone -q "$DPI_URL" "$WORK/mmt-dpi-src"
fi

for ref in "${REFS[@]}"; do
	l=${ref%%=*}; c=$(commit_of "$ref")
	if [ "$l" != "$c" ] && git -C "$WORK/mmt-dpi-src" rev-parse -q --verify "refs/tags/$l^{commit}" >/dev/null \
		&& [ "$(git -C "$WORK/mmt-dpi-src" rev-parse "refs/tags/$l^{commit}")" != "$(git -C "$WORK/mmt-dpi-src" rev-parse "$c^{commit}")" ]; then
		echo "WARNING: mmt-dpi tag $l no longer names $c; measuring $c" >&2
	fi
done

# snapshot of this repository's HEAD commit. The working tree is not used: `make`
# rewrites the tracked src/dpi/mmt_dpi.h, and a regenerated header must not be
# measured as the committed one.
if ! git -C "$REPO" diff --quiet HEAD -- rules src; then
	echo "WARNING: rules/ or src/ differ from HEAD; measuring HEAD $(git -C "$REPO" rev-parse --short HEAD) without them:" >&2
	git -C "$REPO" diff --stat HEAD -- rules src | tail -5 >&2
fi
rm -rf "$WORK/mmt-sec"; mkdir -p "$WORK/mmt-sec"
git -C "$REPO" archive --format=tar HEAD | tar -C "$WORK/mmt-sec" -xf -
git -C "$REPO" rev-parse HEAD > "$WORK/out/mmt-security.commit"
# the Makefile takes GIT_VERSION from git log; keep it meaningful without .git
sed -i "s/^GIT_VERSION := .*/GIT_VERSION := $(git -C "$REPO" log --format=%h -n1)/" "$WORK/mmt-sec/Makefile"

run_one(){
	local ref label out
	ref=$(commit_of "$1"); label=$(label_of "$1")
	out="$WORK/out/$label"
	rm -rf "$out"; mkdir -p "$out"
	docker run --rm \
		-e DPI_REF="$ref" -e OUT_UID="$(id -u)" -e OUT_GID="$(id -g)" \
		-v "$WORK/mmt-dpi-src:/in/mmt-dpi:ro" \
		-v "$WORK/mmt-sec:/in/mmt-sec:ro" \
		-v "$HERE:/in/tool:ro" \
		-v "$out:/out" \
		"$IMAGE" bash /in/tool/in-container.sh \
		> "$out/container.log" 2>&1 \
		&& echo "ok   $label ($ref)" || { echo "FAIL $label (see $out/container.log)"; tail -20 "$out/container.log"; return 1; }
}

pids=(); fail=0
for ref in "${REFS[@]}"; do
	while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n || fail=1; done
	run_one "$ref" &
done
while [ "$(jobs -rp | wc -l)" -gt 0 ]; do wait -n || fail=1; done

labels=()
for ref in "${REFS[@]}"; do labels+=("$WORK/out/$(label_of "$ref")"); done
python3 -I "$HERE/compare.py" "${labels[@]}" | tee "$WORK/out/report.txt"
echo "(scratch: $WORK, $(du -sh "$WORK" | cut -f1); remove it with rm -rf $WORK)" >&2
exit $fail
