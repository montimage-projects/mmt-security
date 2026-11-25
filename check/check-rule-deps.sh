#!/usr/bin/env bash
# rules/%.so must track its rules/%.xml (fork #70), run by `make check` as
# check-rule-deps.
#
# In a scratch copy of the tree (the checked build outputs are untouched):
#   - a fresh `make -n sample_rules` rebuilds nothing;
#   - `touch rules/27.udp_scan.xml` rebuilds rules/27.udp_scan.so, and only
#     that rule;
#   - a second `make` is a no-op;
#   - a newer compile_rule rebuilds every rule (the generator input);
#   - rules/%.c, the STATIC_LINK intermediate, likewise tracks its .xml.
# On a Makefile whose rules/%.so does not list its .xml, the touched rule
# keeps its stale .so - the bug #70 reports - and this script fails.
#
# Usage: check/check-rule-deps.sh
set -u
cd "$(dirname "$0")/.." || exit 1
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing that a rule .so rebuilds when its .xml is newer"

if [ ! -x ./compile_rule ]; then
	echo "  => FAILED: no ./compile_rule - run make first"
	exit 1
fi

B="$TMP/build"
mkdir "$B"
for d in Makefile src rules compile_rule; do
	cp -a "$d" "$B/" || exit 1
done
# .build-flavor is a rules/%.so prerequisite too; copying it when present
# keeps the scratch tree fresh like the checked one (a missing stamp would
# be rewritten on parse and would rebuild everything once)
[ -f .build-flavor ] && cp -a .build-flavor "$B/"
cd "$B" || exit 1

# settle the copy: --refresh-plugin-engine always recompiles plugins_engine.o
# when standalone or lib builds, so the checked tree can carry an object
# newer than compile_rule; make would then relink compile_rule - and every
# rule behind it - on the first leg's dry run and mask the .xml precision
# this script asserts
make -j1 compile_rule sample_rules > "$TMP/settle.log" 2>&1 || {
	cat "$TMP/settle.log"; fail "scratch settle build failed"; }

# count of `compile_rule rules/...` recipe lines a dry run would run
dry_rules(){ make -n "$@" 2>&1 | grep -c 'compile_rule rules/'; }

# leg 1: the fresh copy is up to date
n=$(dry_rules sample_rules)
[ "$n" -eq 0 ] || fail "fresh copy: make -n sample_rules rebuilds $n rules"

# leg 2: a touched xml rebuilds its .so, and only it
touch rules/27.udp_scan.xml
out=$(make -n sample_rules 2>&1 | grep 'compile_rule rules/')
# unquoted $out collapses the recipe's trailing space of an empty RULE_GCC_ARGS
[ "$(echo $out)" = "./compile_rule rules/27.udp_scan.so rules/27.udp_scan.xml" ] || \
	fail "touched rules/27.udp_scan.xml rebuilds '$out', expected only rules/27.udp_scan.so"
make -j1 sample_rules > "$TMP/make.touch.log" 2>&1 || {
	cat "$TMP/make.touch.log"; fail "make sample_rules after touch failed"; }
[ rules/27.udp_scan.so -nt rules/27.udp_scan.xml ] || \
	fail "rules/27.udp_scan.so not newer than its xml after the rebuild"

# leg 3: a second make is a no-op
n=$(dry_rules sample_rules)
[ "$n" -eq 0 ] || fail "second make -n sample_rules rebuilds $n rules"

# leg 4: compile_rule is a generator input of every rule
touch compile_rule
n=$(dry_rules sample_rules)
total=$(find rules -maxdepth 1 -name '*.xml' | wc -l)
[ "$n" -eq "$total" ] || fail "newer compile_rule rebuilds $n rules, expected all $total"

# leg 5: the STATIC_LINK intermediate rules/%.c tracks its .xml as well.
# A scratch rule pair keeps the real rules out of the STATIC_LINK switch's
# flavor-stamp rebuild.
cp rules/27.udp_scan.xml rules/dep_probe.xml
: > rules/dep_probe.c
n=$(make -n STATIC_LINK=1 rules/dep_probe.c 2>&1 | grep -c 'compile_rule')
[ "$n" -eq 0 ] || fail "STATIC_LINK: up-to-date rules/dep_probe.c is remade"
touch rules/dep_probe.xml
out=$(make -n STATIC_LINK=1 rules/dep_probe.c 2>&1 | grep 'compile_rule')
case "$out" in
*"rules/dep_probe.c rules/dep_probe.xml"*) ;;
*) fail "STATIC_LINK: touched rules/dep_probe.xml does not regen its .c (got: '$out')" ;;
esac

if [ "$status" -eq 0 ]; then
	echo "  => OK: a newer xml or compile_rule rebuilds exactly the rules it should"
fi
exit $status
