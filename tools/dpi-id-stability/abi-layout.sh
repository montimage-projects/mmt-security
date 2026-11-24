#!/bin/bash
# abi-layout.sh - layout of the rule ABI structs (rule_info_t, proto_attribute_t,
# rule_version_info_t, message_t, the fsm and instance-key structs, and what
# the guards read of rule_engine_t) at each mmt-security tag (issue #5, A0).
#
# Usage: tools/dpi-id-stability/abi-layout.sh [-w WORKDIR] [-i IMAGE] [TAG...]
#   default TAGs: every v1.2.* tag. Runs one ubuntu container, no sudo.
# Prints "tag  layout-sha256  REQUIRE_PLUGIN" then the lines that changed since
# the previous tag.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=$HERE/.work
IMAGE=ubuntu:24.04
while getopts "w:i:h" o; do
	case $o in w) WORK=$OPTARG ;; i) IMAGE=$OPTARG ;; *) sed -n '2,9p' "$0"; exit 2 ;; esac
done
shift $((OPTIND - 1))
TAGS=("$@")
[ ${#TAGS[@]} -gt 0 ] || mapfile -t TAGS < <(git -C "$REPO" tag -l 'v1.2.*' | sort -V)
mkdir -p "$WORK/abi"; WORK=$(cd "$WORK" && pwd)
rm -rf "$WORK/abi/src"; mkdir -p "$WORK/abi/src"
for t in "${TAGS[@]}"; do
	mkdir -p "$WORK/abi/src/$t"
	git -C "$REPO" archive "$t" src/lib src/dpi | tar -C "$WORK/abi/src/$t" -xf -
	git -C "$REPO" show "$t:src/lib/version.c" | sed -n 's/^#define REQUIRE_PLUGIN "\(.*\)"/\1/p' > "$WORK/abi/src/$t/require"
done
cp "$HERE/abi_layout.c" "$WORK/abi/"
# root inside the container only to install gcc; the output is chowned back
docker run --rm -e OUT_UID="$(id -u)" -e OUT_GID="$(id -g)" -v "$WORK/abi:/abi" "$IMAGE" bash -c '
	set -e
	trap "chown -R \$OUT_UID:\$OUT_GID /abi" EXIT
	command -v gcc >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive \
		apt-get install -y -qq --no-install-recommends gcc libc6-dev >/dev/null; }
	for d in /abi/src/*/; do
		t=$(basename "$d"); def=
		grep -q rule_version_info_t "$d/src/lib/plugin_header.h" && def=-DHAS_VERSION_INFO
		grep -q fsm_instance_key_t "$d/src/lib/plugin_header.h" && def="$def -DHAS_INSTANCE_KEYS"
		grep -q MMT_SEC_MSG_DATA_TYPE_NUMERIC "$d/src/lib/message_t.h" && def="$def -DHAS_MSG_DATA_TYPE_PREFIX"
		if grep -q mmt_sec_rule_engine_get_msg_values "$d/src/lib/gen_code.c"; then def="$def -DHAS_MSG_VALUES_ACCESSOR"
		elif grep -q "_engine->msg_values" "$d/src/lib/gen_code.c"; then def="$def -DHAS_MSG_VALUES_FIELD"; fi
		gcc -w $def -I"$d/src/lib" -I"$d/src/dpi" -o /abi/probe-$t /abi/abi_layout.c
		/abi/probe-$t > /abi/layout-$t.txt
	done' 2>&1
prev=
for t in "${TAGS[@]}"; do
	f=$WORK/abi/layout-$t.txt
	printf "%-8s %s REQUIRE_PLUGIN=%s\n" "$t" "$(sha256sum < "$f" | cut -c1-12)" "$(cat "$WORK/abi/src/$t/require")"
	[ -n "$prev" ] && diff "$prev" "$f" | sed -n 's/^[<>] /    &/p' || true
	prev=$f
done
