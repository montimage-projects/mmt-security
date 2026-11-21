#!/usr/bin/env bash
# Checks of the SMP mode of mmt_sec_standalone (Montimage fork #31, E3), run by
# `make check`: `-c 1-4` used to hang reproducibly on aarch64 - a missing
# release fence in the SPSC ring let a worker pop a stale message_t, corrupt
# the heap, abort, and the abort's signal handler then deadlocked trying to
# join the workers. Each run below must finish inside its timeout.
#
# Usage: check/check-smp.sh [path/to/mmt_sec_standalone]
set -u
cd "$(dirname "$0")/.."
STANDALONE=$(realpath "${1:-./mmt_sec_standalone}")
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing mmt_sec_standalone in SMP mode (-c)"

# a handful of -c runs; none may exceed its bound
run(){ # cores pcap bound
	timeout -s KILL "$3" "$STANDALONE" -c "$1" -t "$2" -f "$TMP/" > "$TMP/log" 2>&1
	rc=$?
	echo "  -c $1 on $(basename "$2") (bound ${3}s): rc=$rc"
	[ "$rc" = 137 ] && fail "mmt_sec_standalone -c $1 hung on $2 (killed after ${3}s)"
	[ "$rc" = 139 ] && fail "mmt_sec_standalone -c $1 crashed on $2"
}

run 1-4 check/pcap/56.57.syn_flood.pcap 60
run 1-4 check/pcap/56.syn_flood_short_tail.pcap 60
run 1-8 check/pcap/15.nikto.pcap 60

# SIGTERM must stop a running instance (it used to deadlock inside the handler)
"$STANDALONE" -c 1-8 -t check/pcap/56.57.syn_flood.pcap -f "$TMP/" > "$TMP/log" 2>&1 &
pid=$!
sleep 1
kill -TERM $pid 2>/dev/null
sleep 9
if kill -0 $pid 2>/dev/null; then
	kill -KILL $pid 2>/dev/null
	fail "mmt_sec_standalone -c 1-8 still running 9 s after SIGTERM"
else
	wait $pid 2>/dev/null
	echo "  -c 1-8 on 56.57.syn_flood.pcap stops on SIGTERM: OK"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
