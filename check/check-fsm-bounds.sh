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
# link the test against the already checked library objects
if ! gcc -O2 -fPIC -Wall -I/usr/include/libxml2 -I"$DPI/include" \
	-o "$TMP/fsm_bounds" check/fsm_bounds.c src/lib/*.o \
	-Wl,--export-dynamic -L"$DPI/lib" -L/usr/local/lib \
	-ldl -lpthread -lxml2 -l:libmmt_tcpip.so -l:libmmt_core.so > "$TMP/build.log" 2>&1; then
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
