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
#   - rules/%.c, the STATIC_LINK intermediate, likewise tracks its .xml;
#   - the generated, tracked src/dpi/mmt_dpi.h matches what the installed
#     MMT-DPI generates - on a fresh clone its checkout mtime is always
#     newer than $(MMT_DPI_DIR), so a Makefile that regenerates only when
#     the directory is newer keeps the stale copy forever and every rule
#     embeds the attribute ids of a DPI other than the installed one
#     (fork #70, review M1);
#   - the installed DPI's file content invalidates the objects: an upgrade
#     in place at the same $(MMT_DPI_DIR) rewrites .build-flavor, rebuilds
#     every object and regenerates every rule (fork #70, review M2);
#   - the Makefile's own content hash sees a change: a cp -a copy of the
#     prefix, settled then changed in one file, moves the stamp and
#     compiles objects - also when $(MMT_DPI_DIR) points at the copy
#     through a symlink (fork #70, review L5/M3).
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

# leg 6: src/dpi/mmt_dpi.h matches what the installed MMT-DPI generates
# (fork #70, review M1). Simulate a fresh clone - the tracked header newer
# than $(MMT_DPI_DIR) - then ask make for the header by its real target
# name ($(MMT_DPI_HEADER) is an absolute path). The reference is generated
# by a generator compiled straight from source: the Makefile under test is
# not trusted to produce it - on the base Makefile nothing regenerates
# here, so the stale tracked copy is compared and fails.
touch src/dpi/mmt_dpi.h
make -j1 "$PWD/src/dpi/mmt_dpi.h" > "$TMP/hdr.log" 2>&1 || {
	cat "$TMP/hdr.log"; fail "make src/dpi/mmt_dpi.h"; }
# where the DPI is installed: the lib dir make exported, else the default
DPI_LIB=${LD_LIBRARY_PATH:-/opt/mmt/dpi/lib}
DPI_DIR=${DPI_LIB%%:*}
DPI_DIR=${DPI_DIR%/lib}
${CC:-gcc} -I"$DPI_DIR/include" -L"$DPI_DIR/lib" -o "$TMP/gen_dpi" src/main_gen_dpi.c \
	-l:libmmt_core.so -ldl > "$TMP/gcc.log" 2>&1 || {
	cat "$TMP/gcc.log"; fail "compiling src/main_gen_dpi.c"; }
LD_LIBRARY_PATH="$DPI_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
	"$TMP/gen_dpi" "$TMP/mmt_dpi.now.h" || fail "the DPI header generator failed"
if [ -f "$TMP/mmt_dpi.now.h" ]; then
	# the first two lines (timestamp, generator path) are volatile, as in the
	# Makefile's own compare
	cmp -s <(sed '1,2d' src/dpi/mmt_dpi.h) <(sed '1,2d' "$TMP/mmt_dpi.now.h") || \
		fail "src/dpi/mmt_dpi.h is stale: it differs from what the installed MMT-DPI generates"
fi

# leg 7: the installed DPI's file content is a build input of every object
# (fork #70, review M2). An upgrade in place swaps files under
# $(MMT_DPI_DIR) but keeps the flag set, the directory mtime and
# .build-flavor's content, so a change that only the files' contents carry
# rebuilt nothing and rules kept embedding the previous DPI's ids. The
# Makefile folds a hash of the installed files (DPI_SIG) into the flavor
# signature: a swap rewrites the stamp while the makefile is read and the
# objects rebuild in the same make; a relinked compile_rule then
# regenerates every rule. Feed make the signature change a swap produces;
# on a Makefile that does not observe the DPI content nothing rebuilds.
exp_objs=$(( $(find src/lib -name '*.c' | wc -l) + 1 ))  # LIB_OBJS + main_gen_plugin.o
touch "$TMP/m2.marker"
make -j1 DPI_SIG=dpi-content-changed compile_rule sample_rules > "$TMP/m2.log" 2>&1 || {
	cat "$TMP/m2.log"; fail "rebuild after a DPI content change"; }
n=$(grep -c '^\[COMPILE\] .*\.o$' "$TMP/m2.log")
[ "$n" -eq "$exp_objs" ] || fail "changed DPI content rebuilds $n objects, expected $exp_objs"
n=$(find rules -maxdepth 1 -name '*.so' -newer "$TMP/m2.marker" | wc -l)
total=$(find rules -maxdepth 1 -name '*.xml' | wc -l)
[ "$n" -eq "$total" ] || fail "changed DPI content regenerates $n rules, expected all $total"
# ...and the signature itself must observe content: hashing a copy of the
# installed dir before and after a planted change must differ. The
# pipeline mirrors the Makefile's, `find -L` included (review M3)
sig_of(){ find -L "$1" -type f -print0 2>/dev/null | sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -d' ' -f1; }
cp -a "$DPI_DIR" "$TMP/dpi-copy"
before=$(sig_of "$TMP/dpi-copy")
f=$(find -L "$TMP/dpi-copy" -type f | head -1)
echo x >> "$f"
after=$(sig_of "$TMP/dpi-copy")
[ "$before" != "$after" ] || \
	fail "the DPI content signature does not observe the installed files' content"

# leg 8: the Makefile's own DPI_SIG pipeline must observe file content,
# not only file names (fork #70, review L5). Leg 7 feeds make the
# signature a swap produces, so a pipeline that stopped hashing content -
# or a find that cannot descend a symlinked $(MMT_DPI_DIR) (review M3) -
# would keep this suite green while a real upgrade rebuilt nothing.
# cp -a the prefix, settle a build against it, change one file's content:
# the stamp's hash field must move and objects must compile. Probe the
# plain copy first, then the same copy through a symlink - a `find`
# without -L hashes empty input for the symlinked prefix and fails.
cp -a "$DPI_DIR" "$TMP/dpi-real"
ln -s "$TMP/dpi-real" "$TMP/dpi-link"
probe_dpi_dir(){
	make -j1 MMT_DPI_DIR="$1" compile_rule > "$TMP/probe.settle.log" 2>&1 || {
		cat "$TMP/probe.settle.log"; fail "real-pipeline probe ($1): settle build failed"; return; }
	s1=$(cut -d' ' -f1 .build-flavor)
	# append where no compile or link can trip on it: a doc file is
	# hashed like everything else under the prefix
	f=$(find -L "$1" -type f -path '*/share/*' | sort | head -1)
	[ -n "$f" ] || f=$(find -L "$1" -type f | sort | head -1)
	echo x >> "$f"
	make -j1 MMT_DPI_DIR="$1" compile_rule > "$TMP/probe.log" 2>&1 || {
		cat "$TMP/probe.log"; fail "real-pipeline probe ($1): rebuild failed"; return; }
	s2=$(cut -d' ' -f1 .build-flavor)
	[ "$s1" != "$s2" ] || {
		fail "real-pipeline probe ($1): a content change left the DPI hash '$s2'"; return; }
	n=$(grep -c '^\[COMPILE\] .*\.o$' "$TMP/probe.log")
	[ "$n" -gt 0 ] || fail "real-pipeline probe ($1): a content change rebuilt 0 objects"
}
probe_dpi_dir "$TMP/dpi-real"
probe_dpi_dir "$TMP/dpi-link"

if [ "$status" -eq 0 ]; then
	echo "  => OK: a newer xml or compile_rule rebuilds exactly the rules it should"
fi
exit $status
