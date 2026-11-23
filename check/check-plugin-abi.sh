#!/usr/bin/env bash
# Plugin ABI gate of the rule loader (fork #51, PR #55 review finding 1),
# run by `make check` as target check-plugin-abi.
#
# A rule .so shares rule_info_t (plugin_header.h) and, through the guards
# that include rule_verif_engine.h, rule_engine_t with the engine. A rule
# built for another layout must be refused by the loader with a warning,
# never loaded (loading one is undefined behaviour: SIGSEGV in
# rule_engine_init or inside the generated guards). The loader keeps a rule
# whose stamp (rule_version_info_t.index, the version of the compile_rule
# that built it) is in [REQUIRE_PLUGIN, version of the engine]:
#  - older: rules built by compile_rule of $MMT_SEC_ABI_BASE (default
#    97441d79, the last commit before instance_keys, which stamped 1.2.20
#    with the old layout). That needs the commit in the clone (not in a
#    shallow CI checkout); without it, the leg builds the rules with this
#    tree's compile_rule stamped 1.2.20 instead, which checks the lower
#    bound but not the old layout;
#  - newer: rules built by this tree's compile_rule stamped one patch
#    version above the engine (a scratch copy built with VERSION=x.y.z+1).
# In both legs the engine must load no rule, name each refused rule, and
# exit 0 on a capture; rule_info must refuse them too. A control leg with
# this tree's rules must alert, so the capture does exercise the rules.
# 6.SYNFUL.so holds two rules: the loader must not index an array of
# another layout beyond its first rule.
#
# Usage: check/check-plugin-abi.sh [compile_rule] [mmt_sec_standalone] [rule_info]
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
COMPILE_RULE=$(realpath "${1:-./compile_rule}")
STANDALONE=$(realpath "${2:-./mmt_sec_standalone}")
RULE_INFO=$(realpath "${3:-./rule_info}")
BASE=${MMT_SEC_ABI_BASE:-97441d79}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

RULES="1.ssh 6.SYNFUL 26.proto_scan"
# rules alerting on $PCAPS in the control leg (rule 1 does not: its .so
# is there for a single-rule plugin)
IDS="6 84 26"
PCAPS="check/pcap/6.SYNFUL.pcap check/pcap/26.protocal_scan.pcap"

VERSION=$(sed -n 's/^VERSION *:= *//p' Makefile)
NEWER=$(echo "$VERSION" | awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }')

echo
echo "Testing the plugin ABI gate of the rule loader (engine $VERSION)"

# make -j1: the tree has a parallel-build race (readme.md)
build_compile_rule(){ # dir [make args...]
	local d=$1; shift
	find "$d" -name "*.o" -delete
	rm -f "$d"/compile_rule
	( cd "$d" && make -j1 "$@" compile_rule ) > "$d.make.log" 2>&1 \
		|| { tail -20 "$d.make.log"; return 1; }
}
copy_tree(){ # dir
	mkdir -p "$1"
	cp -a Makefile src "$1/" || return 1
}
# compile_rule reads the headers of ./src/lib: run it from its own tree
compile_rules(){ # tree out_dir
	local x
	mkdir -p "$2"
	for x in $RULES; do
		( cd "$1" && ./compile_rule "$2/$x.so" "$ROOT/rules/$x.xml" ) > "$2/$x.log" 2>&1 \
			|| { tail -5 "$2/$x.log"; return 1; }
	done
}
# run the engine on the capture with the .so of $1/rules
run_engine(){ # dir log
	local p rc=0
	mkdir -p "$1/out"
	for p in $PCAPS; do
		( cd "$1" && timeout -s KILL 120 "$STANDALONE" -t "$ROOT/$p" -f "$1/out/" ) >> "$2" 2>&1 || rc=$?
		[ $rc -eq 0 ] || break
	done
	return $rc
}
alerts(){ cat "$1"/out/*.csv 2>/dev/null | wc -l; }

# expect every rule of $1/rules refused with message $2, no rule loaded,
# exit 0 on the capture, rule_info refusing each .so as well
check_refused(){ # dir pattern what
	local d=$1 pat=$2 what=$3 rc=0 id n x
	run_engine "$d" "$d/run.log" || rc=$?
	if [ $rc -ne 0 ]; then
		tail -5 "$d/run.log" | sed 's/^/    | /'
		fail "$what: mmt_sec_standalone exited $rc (signal $((rc > 128 ? rc - 128 : 0)))"
		return
	fi
	n=$(alerts "$d")
	[ "$n" -eq 0 ] || fail "$what: $n alert(s): a refused rule was loaded"
	# rules 1, 6 and 26 are the first rule of their .so; 84 is the second
	# of 6.SYNFUL.so, refused with it
	for id in 1 6 26; do
		grep -q "Ignored rule $id as $pat" "$d/run.log" \
			|| fail "$what: no \"Ignored rule $id as $pat\" warning"
	done
	grep -q "Ignored the 1 other rule(s) of the same plugin" "$d/run.log" \
		|| fail "$what: rule 84 (second rule of 6.SYNFUL.so) not refused with its plugin"
	for x in $RULES; do
		rc=0
		( cd "$d" && timeout -s KILL 60 "$RULE_INFO" "rules/$x.so" ) > "$d/info-$x.log" 2>&1 || rc=$?
		if [ $rc -ne 0 ]; then
			tail -3 "$d/info-$x.log" | sed 's/^/    | /'
			fail "$what: rule_info rules/$x.so exited $rc"
		elif ! grep -q "^Found 0 rule" "$d/info-$x.log"; then
			fail "$what: rule_info lists the rules of rules/$x.so"
		fi
	done
	[ $status -eq 0 ] && echo "  $what: refused, no alert, exit 0"
}

# control: this tree's rules load and alert on the same captures
C=$TMP/control
compile_rules "$ROOT" "$C/rules" || fail "control: compile_rule failed"
run_engine "$C" "$C/run.log" || fail "control: mmt_sec_standalone failed"
n=$(alerts "$C")
for id in $IDS; do
	cat "$C"/out/*.csv 2>/dev/null | awk -F, -v r=$id '$5 == r' | grep -q . \
		|| fail "control: rule $id does not alert"
done
echo "  control (this tree's rules): $n alert(s)"

# older: rules of the layout before instance_keys
O=$TMP/older
if git -C "$ROOT" cat-file -e "$BASE^{commit}" 2>/dev/null; then
	mkdir -p "$O/tree"
	git -C "$ROOT" archive "$BASE" Makefile src | tar -C "$O/tree" -xf - \
		|| fail "older: git archive $BASE failed"
	what="older ($BASE, stamped $(git -C "$ROOT" show "$BASE:Makefile" | sed -n 's/^VERSION *:= *//p'), old layout)"
	build_compile_rule "$O/tree" || fail "older: compile_rule of $BASE does not build"
else
	echo "  older: commit $BASE not in this clone: stamping 1.2.20 with this tree's layout"
	copy_tree "$O/tree" || fail "older: copy failed"
	what="older (stamped 1.2.20, this layout)"
	build_compile_rule "$O/tree" VERSION=1.2.20 || fail "older: compile_rule VERSION=1.2.20 does not build"
fi
if [ $status -eq 0 ]; then
	compile_rules "$O/tree" "$O/rules" || fail "$what: compile_rule failed"
	[ $status -eq 0 ] && check_refused "$O" "it is not up to date" "$what"
fi

# newer: rules stamped one patch version above this engine
N=$TMP/newer
copy_tree "$N/tree" || fail "newer: copy failed"
what="newer (stamped $NEWER)"
if build_compile_rule "$N/tree" VERSION="$NEWER"; then
	compile_rules "$N/tree" "$N/rules" || fail "$what: compile_rule failed"
	[ $status -eq 0 ] && check_refused "$N" "it was built for a newer engine" "$what"
else
	fail "$what: compile_rule does not build"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
