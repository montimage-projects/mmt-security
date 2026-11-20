#!/bin/bash
# header-regen.sh - when does `make` regenerate src/dpi/mmt_dpi.h, and which ids
# does compile_rule then bake? (issue #5, A0, review of PR #9)
#
# Usage: tools/dpi-id-stability/header-regen.sh [-w WORKDIR] [-i IMAGE]
#   WORKDIR  scratch directory (default: tools/dpi-id-stability/.work/regen)
#   IMAGE    base image (default: ubuntu:24.04, pinned by digest below)
#
# Downloads the mmt-dpi v1.10.2 and v1.10.3 release .debs for ubuntu-24.04 and
# this machine's arch, checks them against each release's SHA256SUMS, and runs
# header-regen-in.sh in one container on a `git archive HEAD` of this repository.
# The transcript (commands and their output) goes to stdout and WORKDIR/regen.log.
# Needs docker (user in the docker group), git and curl; no sudo.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$HERE/.work/regen
# ubuntu:24.04 as of 2026-11-20 (multi-arch index digest)
IMAGE=ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
while getopts "w:i:h" o; do
	case $o in w) WORK=$OPTARG ;; i) IMAGE=$OPTARG ;; *) sed -n '2,13p' "$0"; exit 2 ;; esac
done
mkdir -p "$WORK/debs"; WORK=$(cd "$WORK" && pwd)

ARCH=$(uname -m)
REL=https://github.com/Montimage/mmt-dpi/releases/download
for vb in 1.10.2_a84a6050 1.10.3_6a0afb46; do
	v=${vb%_*}; f=mmt-dpi_${vb}_ubuntu-24.04_${ARCH}.deb
	mkdir -p "$WORK/debs/$v"
	( cd "$WORK/debs/$v"
	  [ -f "$f" ] || curl -fsSLO "$REL/v$v/$f"
	  curl -fsSL -o SHA256SUMS "$REL/v$v/SHA256SUMS"
	  grep " $f\$" SHA256SUMS | sha256sum -c --quiet - )
	ln -sf "$v/$f" "$WORK/debs/mmt-dpi_$v.deb"
done

git -C "$REPO" archive --format=tar HEAD > "$WORK/sec.tar"
git -C "$REPO" rev-parse HEAD > "$WORK/sec.commit"

docker run --rm -e OUT_UID="$(id -u)" -e OUT_GID="$(id -g)" \
	-v "$WORK:/w" -v "$HERE:/in/tool:ro" "$IMAGE" \
	bash /in/tool/header-regen-in.sh 2>&1 | tee "$WORK/regen.log"
