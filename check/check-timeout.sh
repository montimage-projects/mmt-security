#!/usr/bin/env bash
# Checks of the timeout scan of _process_multi_packets() (Montimage fork #31,
# E2), run by `make check`. The test rules check/timeout/*.xml are compiled
# into a temporary rules/ folder (they are not installed) and run on
# check/timeout/timeout.pcap (check/gen/timeout_pcap.py):
#  - 9101 is "a NOT b within 1 s": its only path to a verdict is the timeout
#    transition, so the alert must come from the scan, on the unrelated
#    datagram of t=2.5 (event_2), about 2.5 s after event_1 at t=0. A second
#    instance whose b arrives in time (t=5.5) must not alert.
#  - 9102 is "a THEN b within 1 s": b in time (t=10.5) alerts; b that is late
#    (t=16.5, after the 1 s deadline) must not.
#
# On main the timeout scan never runs, so rule 9101 never reports.
#
# Usage: check/check-timeout.sh [path/to/compile_rule] [path/to/mmt_sec_standalone]
set -u
cd "$(dirname "$0")/.."
COMPILE_RULE=$(realpath "${1:-./compile_rule}")
STANDALONE=$(realpath "${2:-./mmt_sec_standalone}")
DIR=$PWD/check/timeout
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing the timeout scan of the rule verification engine"
mkdir "$TMP/rules" "$TMP/out"
for xml in "$DIR"/*.xml; do
	id=$(basename "$xml" .xml)
	if ! "$COMPILE_RULE" "$TMP/rules/$id.so" "$xml" > "$TMP/$id.log" 2>&1; then
		fail "rule $id does not compile"
		grep -iE "error" "$TMP/$id.log" | head -5 | sed 's/^/    | /'
	fi
done
# the standalone loads every .so of ./rules
( cd "$TMP" && "$STANDALONE" -t "$DIR/timeout.pcap" -f "$TMP/out/" > "$TMP/run.log" 2>&1 ) \
	|| { cat "$TMP/run.log"; fail "mmt_sec_standalone failed"; }

csv=$(cat "$TMP"/out/*.csv 2>/dev/null)
# alert count per rule
got(){ printf '%s\n' "$csv" | awk -F, -v r="$1" '$5 == r' | wc -l; }
n91=$(got 9101); n92=$(got 9102)
echo "  rule 9101: $n91 alert(s), rule 9102: $n92 alert(s)"
[ "$n91" = 1 ] || fail "rule 9101 (a NOT b) alerts $n91 times, expected 1 (timeout transition)"
[ "$n92" = 1 ] || fail "rule 9102 (a THEN b) alerts $n92 times, expected 1 (only the b in time)"

# rule 9101: event_1 is the datagram of t=0, event_0 is the timeout event
# carrying the message of t=2.5: the verdict is due after the matching event
ts1=$(printf '%s\n' "$csv" | awk -F, '$5 == 9101' | grep -oE '"event_1":\{"timestamp":[0-9.]*' | grep -oE '[0-9.]*$')
ts2=$(printf '%s\n' "$csv" | awk -F, '$5 == 9101' | grep -oE '"event_0":\{"timestamp":[0-9.]*' | grep -oE '[0-9.]*$')
if [ -n "$ts1" ] && [ -n "$ts2" ]; then
	awk -v a="$ts1" -v b="$ts2" 'BEGIN{ exit !(b >= a + 2) }' \
		|| fail "rule 9101: event_0 ($ts2) should be the timeout message ~2.5 s after event_1 ($ts1)"
else
	[ "$n91" = 0 ] || fail "rule 9101: cannot read event timestamps in the alert"
fi

# rule 9102: the alert is on event_2, the datagram of t=10.5 that arrived in time
t2=$(printf '%s\n' "$csv" | awk -F, '$5 == 9102' | grep -oE '"event_2":\{"timestamp":[0-9.]*' | grep -oE '[0-9.]*$')
[ -n "$t2" ] && awk -v b="$t2" 'BEGIN{ exit !(b >= 1795200010 && b < 1795200011) }' \
	|| [ -z "$t2" ] || fail "rule 9102: alert is on event_2 at $t2, expected the t=10.5 datagram"

[ $status -eq 0 ] && echo "  => OK"
exit $status
