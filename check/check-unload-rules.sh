#!/usr/bin/env bash
# Unload then load of rule plugins at the engine level (issue #58), run by
# `make check` as target check-unload-rules. check/unload_rules.c:
#  - unloads one rule of a multi-rule plugin (6.SYNFUL.so: rules 6 and 84)
#    and all the rules of a plugin (1.ssh.so), then loads plugins again -
#    the same ones and another one (26.proto_scan.so, and 9101.so through
#    mmt_sec_load_plugin) - checking the counts and the loaded rule ids after
#    each step, then runs the engine on check/pcap/6.SYNFUL.pcap where the
#    reloaded rules 6 and 84 must still alert.
#  - then unloads down to plugins_count == 0 through the edge cases of the
#    unload paths (same id twice and a nonexistent id, the last slot of a
#    plugin's rules[] and the last slot of plugins[]), and lets a rescan
#    load the rules folder back into the emptied arrays.
# Before the fix, the vacated slot of plugins[] kept its stale rules_count,
# so the reload wrote past the new plugin->rules array (ASan reports a
# heap-buffer-overflow; valgrind an invalid write), and the global rules
# set kept pointing at rules of dlclose()d plugins.
#
# Usage: check/check-unload-rules.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing unload then load of rule plugins (issue #58)"

DPI="${MMT_BASE:-/opt/mmt}/dpi"
# same recipe as the Makefile's test.% rule: link the test against the
# already checked library objects; when the tree was built with `make ASAN=1`
# or `make TSAN=1` the objects reference the sanitizer runtime, so the test
# must compile and link with the same flag (as check-fsm-bounds.sh does)
san=
nm src/lib/*.o 2>/dev/null | grep -q ' __asan_' && san=-fsanitize=address
nm src/lib/*.o 2>/dev/null | grep -q ' __tsan_' && san=-fsanitize=thread
# src/lib/*.gen.o are the sanitizer-free compile_rule objects of an ASAN/TSAN
# build: they duplicate the checked objects' symbols and must be left out
if ! gcc -O2 -fPIC -Wall -I/usr/include/libxml2 -I"$DPI/include" -Isrc/lib $san \
	-o "$TMP/unload_rules" check/unload_rules.c $(ls src/lib/*.o | grep -v '\.gen\.o$') \
	-Wl,--export-dynamic -L"$DPI/lib" -L/usr/local/lib \
	-ldl -lpthread -lxml2 -lpcap -l:libmmt_tcpip.so -l:libmmt_core.so > "$TMP/build.log" 2>&1; then
	cat "$TMP/build.log"
	fail "cannot build check/unload_rules.c"
	echo "  (needs: make _prepare, and the mmt-dpi dev headers)"
	exit $status
fi

# 9101.so: the plugin loaded by functions (mmt_sec_load_plugin)
if ! ./compile_rule "$TMP/9101.so" check/timeout/9101.xml > "$TMP/9101.log" 2>&1; then
	cat "$TMP/9101.log"
	fail "rule 9101 does not compile"
	exit $status
fi

# a scratch run dir: rules/ holds the plugins of the first load, staging/
# the ones moved in or out between the phases (see check/unload_rules.c)
mkdir -p "$TMP/run/rules" "$TMP/run/staging"
cp rules/1.ssh.so rules/11.ip_size.so rules/6.SYNFUL.so "$TMP/run/rules/"
cp rules/26.proto_scan.so "$TMP/run/staging/"
cp "$TMP/9101.so" "$TMP/run/staging/"
cp mmt-security.conf "$TMP/run/"

# $VALGRIND wraps the run, as $(VALGRIND) does for the pcap checks (`make
# check VAL=1`): e.g. VALGRIND="valgrind --error-exitcode=9"
( cd "$TMP/run" && ${VALGRIND:-} "$TMP/unload_rules" "$ROOT/check/pcap/6.SYNFUL.pcap" ) \
	> "$TMP/run.log" 2>&1
rc=$?
cat "$TMP/run.log"
if [ $rc -ne 0 ]; then
	fail "check/unload_rules exited $rc (see the log above)"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
