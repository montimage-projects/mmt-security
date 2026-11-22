#!/usr/bin/env bash
# Bounds checks of mmt_fsm.c (fork #48 review, F2), run by `make check` as
# target check-fsm-bounds. An out-of-range transition_index or a
# current_event_id outside the execution trace is a corruption precursor:
# unreachable on valid input. In a release build the fsm rejects them, but
# before this check it did so silently - now an mmt_error must be emitted.
# check/fsm_bounds.c crafts both cases against the checked objects.
#
# Usage: check/check-fsm-bounds.sh
set -u
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing the bounds checks of mmt_fsm.c"

DPI="${MMT_BASE:-/opt/mmt}/dpi"
# same recipe as the Makefile's test.% rule, minus the mmt-dpi header target:
# link the test against the already checked library objects - except
# mmt_fsm.o, the unit under test, which is rebuilt here in release mode
# (no -DDEBUG_MODE): in a `make DEBUG=1` tree, e.g. CI, the bounds
# checks are pre-empted by mmt_halt()s that exit() the process, so the
# release path this check verifies would never run. DEBUG_MODE changes
# no struct layout, so mixing the release object with the others is safe
# if the tree was built with `make TSAN=1` the objects reference the TSan
# runtime, so the test must compile and link with -fsanitize=thread too
san=
nm src/lib/*.o 2>/dev/null | grep -q ' __tsan_' && san=-fsanitize=thread
if ! gcc -O2 -fPIC -Wall -I/usr/include/libxml2 -I"$DPI/include" $san \
	-c -o "$TMP/mmt_fsm.o" src/lib/mmt_fsm.c 2> "$TMP/build.log"; then
	cat "$TMP/build.log"
	fail "cannot build src/lib/mmt_fsm.c in release mode"
elif ! gcc -O2 -fPIC -Wall -I/usr/include/libxml2 -I"$DPI/include" $san \
	-o "$TMP/fsm_bounds" check/fsm_bounds.c "$TMP/mmt_fsm.o" \
	$(ls src/lib/*.o | grep -v '/mmt_fsm\.o$') \
	-Wl,--export-dynamic -L"$DPI/lib" -L/usr/local/lib \
	-ldl -lpthread -lxml2 -l:libmmt_tcpip.so -l:libmmt_core.so >> "$TMP/build.log" 2>&1; then
	cat "$TMP/build.log"
	fail "cannot build check/fsm_bounds.c"
elif ! "$TMP/fsm_bounds" > "$TMP/run.log" 2>&1; then
	cat "$TMP/run.log"
	fail "check/fsm_bounds: a bounds check did not fire"
else
	grep -q "transition_index" "$TMP/run.log" \
		|| fail "no mmt_error for the out-of-bounds transition_index"
	grep -q "current_event_id" "$TMP/run.log" \
		|| fail "no mmt_error for the out-of-bounds current_event_id"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
