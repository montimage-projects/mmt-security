#!/bin/bash
# The DICOM rules share two blocks of embedded C, kept in check/gen/dicom/blocks/:
#   pdu_track.c   the PDU boundary tracker, in the rules listed in TRACK
#   dimse_walk.c  the DIMSE command set walker, in the rules listed in WALK
# Each copy runs from the block's first line to its last ("---- end of ..."),
# in rules/<rule>.xml and in its mirror rules/properties_all/<rule>.xml.
#
#   check/dicom-blocks.sh [-I <mmt-dpi include dir>]
#       fail when a file has no copy of a block or more than one, when a copy
#       differs from its block, when a mirror differs from its rule, or when the
#       embedded C of one of these rules or of 223 does not compile on its own
#       (without the preamble that compile_rule adds)
#   check/dicom-blocks.sh --write
#       write the blocks into the rules and their mirrors
set -u
cd "$(dirname "$0")/.."

BLOCKS=check/gen/dicom/blocks
TRACK="200 208 209 216 219 220 221 224 226 227 228"
WALK="201 202 213"
INC=/opt/mmt/dpi/include
WRITE=0
while [ $# -gt 0 ]; do
	case "$1" in
	--write) WRITE=1 ;;
	-I) INC=$2; shift ;;
	*) echo "usage: $0 [--write] [-I <mmt-dpi include dir>]" >&2; exit 2 ;;
	esac
	shift
done

rule_file() { ls rules/"$1".*.xml 2>/dev/null | head -1; }

# extract <file> <block>: the copy of <block> in <file>
extract() {
	local first last
	first=$(head -1 "$2")
	last=$(tail -1 "$2")
	awk -v a="$first" -v b="$last" '$0 == a { on = 1 } on { print } on && $0 == b { exit }' "$1"
}

# splice <file> <block>: replace the copy of <block> in <file>
splice() {
	local first last tmp
	first=$(head -1 "$2")
	last=$(tail -1 "$2")
	tmp=$(mktemp)
	awk -v a="$first" -v b="$last" -v blk="$2" '
		$0 == a { while ((getline l < blk) > 0) print l; skip = 1; next }
		skip && $0 == b { skip = 0; next }
		!skip { print }' "$1" > "$tmp" && cat "$tmp" > "$1"
	rm -f "$tmp"
}

fail=0
for pair in "$TRACK:pdu_track.c" "$WALK:dimse_walk.c"; do
	block=$BLOCKS/${pair##*:}
	for id in ${pair%%:*}; do
		f=$(rule_file "$id")
		if [ -z "$f" ]; then echo "  => missing rule $id"; fail=1; continue; fi
		for g in "$f" "rules/properties_all/$(basename "$f")"; do
			# exactly one copy: extract and splice see only the first
			n=$(grep -cxF "$(head -1 "$block")" "$g")
			if [ "$n" -ne 1 ]; then
				if [ "$n" -eq 0 ]; then echo "  => $g: no copy of $block"
				else echo "  => $g: $n copies of the first line of $block, not one"; fi
				fail=1; continue
			fi
			if [ $WRITE -eq 1 ]; then
				splice "$g" "$block"
			elif ! extract "$g" "$block" | diff -u "$block" - > /dev/null; then
				echo "  => $g: the copy of $block differs (check/dicom-blocks.sh --write rewrites it):"
				extract "$g" "$block" | diff -u "$block" - | head -20
				fail=1
			fi
		done
	done
done
[ $WRITE -eq 1 ] && exit $fail

# these rules (the blocks' and 223): the mirror is identical, and the embedded C
# compiles on its own
CC=${CC:-cc}
for id in $TRACK $WALK 223; do
	f=$(rule_file "$id")
	m="rules/properties_all/$(basename "$f")"
	if ! cmp -s "$f" "$m"; then echo "  => $m differs from $f"; fail=1; fi
	grep -q '<!\[CDATA\[' "$f" || continue
	if ! awk '/<!\[CDATA\[/ { on = 1; sub(/.*<!\[CDATA\[/, "") } on && /\]\]>/ { sub(/\]\]>.*/, ""); print; exit } on { print }' "$f" \
			| $CC -fsyntax-only -Wall -Wno-unused-function -Werror -I"$INC" -x c - ; then
		echo "  => $f: the embedded C does not compile on its own"
		fail=1
	fi
done
[ $fail -eq 0 ] && echo "The DICOM rules' shared C blocks match check/gen/dicom/blocks/, and their C compiles on its own"
exit $fail
