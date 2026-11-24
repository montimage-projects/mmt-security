#!/usr/bin/env bash
# Plugin ABI gate of the rule loader (fork #51, PR #55 review finding 1;
# fork #56), run by `make check` as target check-plugin-abi.
#
# A rule .so shares rule_info_t (plugin_header.h), the structs of
# message_t.h and mmt_fsm.h, and the functions it calls with the engine.
# Since 1.2.22 rule_engine_t is not among them: the generated guards read
# the message values through mmt_sec_rule_engine_get_msg_values(), and
# rule_verif_engine.h, which they include, keeps the struct opaque. A 1.2.21
# rule still reads rule_engine_t.msg_values at its compiled-in offset.
# A rule built for another layout must be refused by the loader with a
# warning, never loaded (loading one is undefined behaviour: SIGSEGV in
# rule_engine_init or inside the generated guards). The loader keeps a rule
# whose stamp (rule_version_info_t.index, the version of the compile_rule
# that built it) is in [REQUIRE_PLUGIN, version of the engine]:
#  - older: rules built by compile_rule of $MMT_SEC_ABI_BASE (default
#    97441d79, the last commit before instance_keys, which stamped 1.2.20
#    with the old layout);
#  - 1.2.21: rules built by compile_rule of $MMT_SEC_ABI_BASE_1221
#    (default 3904b83c, the last commit whose guards read
#    rule_engine_t.msg_values, stamped 1.2.21).
#    Both need the commit in the clone (not in a shallow CI checkout);
#    without it, the leg builds the rules with this tree's compile_rule
#    stamped 1.2.20 or 1.2.21 instead, which checks the lower bound but
#    not the old layout;
#  - newer: rules built by this tree's compile_rule stamped one patch
#    version above the engine (a scratch copy built with VERSION=x.y.z+1).
# In these legs the engine must load no rule, name each refused rule, and
# exit 0 on a capture; rule_info must refuse them too. A control leg with
# this tree's rules must alert, so the capture does exercise the rules,
# and its .so must call the accessor. A hand-made plugin whose rule has no
# version stamp (a NULL rule_info_t.version) is refused too, and a guard
# that dereferenced rule_engine_t would not compile.
# 6.SYNFUL.so holds two rules: the loader must not index an array of
# another layout beyond its first rule. Each refused leg also holds 9101
# (check/timeout) built by this tree: a rule of the right version in the
# same rules/ must still load (and an engine built with DEBUG=1 halts when
# no rule at all is loaded: a 0-size allocation in mmt_single_sec_register).
#
# Usage: check/check-plugin-abi.sh [compile_rule] [mmt_sec_standalone] [rule_info]
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
COMPILE_RULE=$(realpath "${1:-./compile_rule}")
STANDALONE=$(realpath "${2:-./mmt_sec_standalone}")
RULE_INFO=$(realpath "${3:-./rule_info}")
BASE=${MMT_SEC_ABI_BASE:-97441d79}
BASE_1221=${MMT_SEC_ABI_BASE_1221:-3904b83c}
CC=${CC:-gcc}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
# leg: failures of the current leg, which stops it; the next leg still runs
fail(){ echo "  => FAILED: $*"; status=1; leg=1; }
leg=0

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
# alerts of the rules under test (9101, the rule of this tree, may alert)
alerts(){ cat "$1"/out/*.csv 2>/dev/null | awk -F, '$5 == 1 || $5 == 6 || $5 == 84 || $5 == 26' | wc -l; }

# expect every rule of $1/rules refused with message $2, no rule loaded,
# exit 0 on the capture, rule_info refusing each .so as well
check_refused(){ # dir pattern what
	local d=$1 pat=$2 what=$3 rc=0 id n x
	( cd "$ROOT" && "$COMPILE_RULE" "$d/rules/9101.so" check/timeout/9101.xml ) > "$d/9101.log" 2>&1 \
		|| { fail "$what: rule 9101 of this tree does not compile"; return; }
	run_engine "$d" "$d/run.log" || rc=$?
	if [ $rc -ne 0 ]; then
		tail -5 "$d/run.log" | sed 's/^/    | /'
		# the engine's fault handler exits with the signal number (11: SIGSEGV)
		fail "$what: mmt_sec_standalone exited $rc"
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
	! grep -q "Ignored rule 9101\|no security rules" "$d/run.log" \
		|| fail "$what: rule 9101 of this tree was not loaded"
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
	[ $leg -eq 0 ] && echo "  $what: refused, no alert, exit 0"
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

# the .so of this tree reach rule_engine_t through the accessor only
leg=0
for x in $RULES; do
	nm -D --undefined-only "$C/rules/$x.so" 2>/dev/null | grep -qw mmt_sec_rule_engine_get_msg_values \
		|| fail "control: rules/$x.so does not call mmt_sec_rule_engine_get_msg_values"
done
# rule_verif_engine.h, the header of the generated guards, keeps
# rule_engine_t opaque: a guard reading its layout does not compile
printf '#include "rule_verif_engine.h"\nconst void *f( const rule_engine_t *e ){ return e; }\n' > "$TMP/opaque-ok.c"
printf '#include "rule_verif_engine.h"\nsize_t f( const rule_engine_t *e ){ return sizeof( *e ); }\n' > "$TMP/opaque-ko.c"
if ! "$CC" -fsyntax-only -I src/lib -I src/dpi "$TMP/opaque-ok.c" > "$TMP/opaque-ok.log" 2>&1; then
	tail -3 "$TMP/opaque-ok.log" | sed 's/^/    | /'
	fail "opaque: rule_verif_engine.h does not compile on its own"
elif "$CC" -fsyntax-only -I src/lib -I src/dpi "$TMP/opaque-ko.c" > /dev/null 2>&1; then
	fail "opaque: rule_verif_engine.h defines rule_engine_t: the guards can read its layout"
fi
[ $leg -eq 0 ] && echo "  this tree's rules call the accessor; rule_engine_t is opaque to them"

# rules built by compile_rule of commit $2, or by this tree's stamped $3
older_leg(){ # name commit stamp layout
	local name=$1 base=$2 stamp=$3 layout=$4 d=$TMP/$1
	leg=0
	if git -C "$ROOT" cat-file -e "$base^{commit}" 2>/dev/null; then
		mkdir -p "$d/tree"
		git -C "$ROOT" archive "$base" Makefile src | tar -C "$d/tree" -xf - \
			|| fail "$name: git archive $base failed"
		what="$name ($base, stamped $(git -C "$ROOT" show "$base:Makefile" | sed -n 's/^VERSION *:= *//p'), $layout)"
		build_compile_rule "$d/tree" || fail "$name: compile_rule of $base does not build"
	else
		echo "  $name: commit $base not in this clone: stamping $stamp with this tree's layout"
		copy_tree "$d/tree" || fail "$name: copy failed"
		what="$name (stamped $stamp, this layout)"
		build_compile_rule "$d/tree" VERSION="$stamp" || fail "$name: compile_rule VERSION=$stamp does not build"
	fi
	if [ $leg -eq 0 ]; then
		compile_rules "$d/tree" "$d/rules" || fail "$what: compile_rule failed"
		[ $leg -eq 0 ] && check_refused "$d" "it is not up to date" "$what"
	fi
}
# older: rules of the layout before instance_keys
older_leg older "$BASE" 1.2.20 "old layout"
# 1.2.21: guards that read rule_engine_t.msg_values at its 1.2.21 offset
older_leg 1.2.21 "$BASE_1221" 1.2.21 "guards read rule_engine_t"

# no version stamp: a hand-made plugin whose rule_info_t.version is NULL
leg=0
V=$TMP/noversion
mkdir -p "$V/rules" "$V/out"
cat > "$V/noversion.c" <<'CEOF'
#include "plugin_header.h"
static const rule_info_t rules[] = {{ .id = 9301, .description = "no version stamp" }};
size_t mmt_sec_get_plugin_info( const rule_info_t **r ){ *r = rules; return 1; }
CEOF
# with rule 9101 of this tree, which must still load (see check_refused)
if ! "$CC" -fPIC -shared -I src/lib -I src/dpi -o "$V/rules/9301.so" "$V/noversion.c" > "$V/cc.log" 2>&1; then
	tail -3 "$V/cc.log" | sed 's/^/    | /'
	fail "no version: the plugin does not compile"
elif ! "$COMPILE_RULE" "$V/rules/9101.so" check/timeout/9101.xml > "$V/9101.log" 2>&1; then
	fail "no version: rule 9101 of this tree does not compile"
else
	rc=0
	( cd "$V" && timeout -s KILL 120 "$STANDALONE" -t "$ROOT/check/pcap/6.SYNFUL.pcap" -f "$V/out/" ) > "$V/run.log" 2>&1 || rc=$?
	if [ $rc -ne 0 ]; then
		tail -5 "$V/run.log" | sed 's/^/    | /'
		fail "no version: mmt_sec_standalone exited $rc"
	fi
	grep -q "Ignored rule 9301 as it has no version stamp" "$V/run.log" \
		|| fail "no version: no \"Ignored rule 9301 as it has no version stamp\" warning"
	! grep -q "Ignored rule 9101\|no security rules" "$V/run.log" \
		|| fail "no version: rule 9101 of this tree was not loaded"
	rc=0
	( cd "$V" && timeout -s KILL 60 "$RULE_INFO" rules/9301.so ) > "$V/info.log" 2>&1 || rc=$?
	if [ $rc -ne 0 ]; then
		tail -3 "$V/info.log" | sed 's/^/    | /'
		fail "no version: rule_info rules/9301.so exited $rc"
	elif ! grep -q "^Found 0 rule" "$V/info.log"; then
		fail "no version: rule_info lists the rule of rules/9301.so"
	fi
	[ $leg -eq 0 ] && echo "  no version stamp: refused, exit 0"
fi

# newer: rules stamped one patch version above this engine
leg=0
N=$TMP/newer
copy_tree "$N/tree" || fail "newer: copy failed"
what="newer (stamped $NEWER)"
if build_compile_rule "$N/tree" VERSION="$NEWER"; then
	compile_rules "$N/tree" "$N/rules" || fail "$what: compile_rule failed"
	[ $leg -eq 0 ] && check_refused "$N" "it was built for a newer engine" "$what"
else
	fail "$what: compile_rule does not build"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
