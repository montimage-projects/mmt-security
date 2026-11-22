#!/usr/bin/env bash
# Checks of the SMP mode of mmt_sec_standalone (Montimage fork #31, E3), run by
# `make check`: `-c 1-8` used to hang on a SYN flood on aarch64 (`-c 1-4` did
# not hang in the issue's measurements): a missing release fence in the SPSC
# ring let a worker pop a stale message_t, corrupt the heap, abort, and the
# abort's signal handler then deadlocked trying to join the workers. Each run
# below must finish inside its timeout and give the expected alert count: the
# `-c 1` run of the same capture, or a committed expectation for the
# generated flood (see below).
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

# the reproducer flood of fork #31 (20 000 SYNs + tail), generated here so the
# large pcap is never committed; it used to hang `-c 1-8` on every run
FLOOD="$TMP/smp_flood.pcap"
# a bigger flood for the SIGTERM leg: it runs several seconds under `-c 1-8`
# even on a fast machine, so the TERM reaches a live process
FLOOD_TERM="$TMP/smp_flood_term.pcap"
if gcc -O2 -o "$TMP/smp_flood_gen" check/gen/smp_flood_gen.c \
	&& "$TMP/smp_flood_gen" "$FLOOD" 20000 \
	&& "$TMP/smp_flood_gen" "$FLOOD_TERM" 80000; then
	: # generated
else
	fail "cannot generate the SMP flood pcap from check/gen/smp_flood_gen.c"
fi

# the reference for one pcap: its alert count under `-c 1`; fails (rc 1) when
# `-c 1` itself exits nonzero or reports no alert, so a build without rules
# cannot pass the SMP legs either
reference(){ # pcap
	local n
	rm -f "$TMP"/mmt-security*.csv
	timeout -s KILL 300 "$STANDALONE" -c 1 -t "$1" -f "$TMP/" > "$TMP/ref.log" 2>&1
	n=$(cat "$TMP"/mmt-security*.csv 2>/dev/null | wc -l)
	echo "$n"
	[ "$n" -gt 0 ]
}

# a handful of -c runs; each must finish inside its bound with rc 0 and give
# the expected alert count: its `-c 1` run of the same capture, or $4 when a
# committed expectation is given instead
run(){ # cores pcap bound [expected]
	local expected n rc
	if [ $# -ge 4 ]; then
		expected=$4
	else
		expected=$(reference "$2") || fail "mmt_sec_standalone -c 1 on $2 gives no alert (nonzero exit or no rules built?)"
	fi
	rm -f "$TMP"/mmt-security*.csv
	timeout -s KILL "$3" "$STANDALONE" -c "$1" -t "$2" -f "$TMP/" > "$TMP/log" 2>&1
	rc=$?
	n=$(cat "$TMP"/mmt-security*.csv 2>/dev/null | wc -l)
	echo "  -c $1 on $(basename "$2") (bound ${3}s): rc=$rc, $n alert(s), expected $expected"
	[ "$rc" -ne 0 ] && fail "mmt_sec_standalone -c $1 exits $rc on $2"
	[ "$n" != "$expected" ] && fail "mmt_sec_standalone -c $1 gives $n alert(s) on $2, expected $expected"
}

run 1-4 check/pcap/56.57.syn_flood.pcap 60
run 1-4 check/pcap/56.syn_flood_short_tail.pcap 60
run 1-8 check/pcap/15.nikto.pcap 60
#the flood's `-c 1-8` leg takes ~75-120 s idle, and >240 s when the machine
#is already loaded (several builds/checks at once); the bound only needs to
#be comfortably above the worst legit duration to catch the old infinite
#hang, so it is 600 s. Its expected count is committed in
#check/smp_flood.expect, not measured by a `-c 1` reference run: that run
#needs 400-525 s on a slow or loaded machine (rockylinux:9, aarch64) -
#longer than the leg it references - so `make check` could not pass there
#(fork #48 review, F1). The pcap is deterministic (fixed-seed generator,
#check/gen/smp_flood_gen.c), so the count is stable; refresh it after a
#change to rules 56/57 or to the generator with:
#  ./mmt_sec_standalone -c 1 -t <flood> -f out/ && wc -l out/mmt-security*.csv
run 1-8 "$FLOOD" 600 "$(cat check/smp_flood.expect)"

# SIGTERM must stop a running instance (it used to deadlock inside the
# handler): the generated flood runs several seconds under `-c 1-8`, so the
# TERM reaches a live process and the run must then end inside its bound
"$STANDALONE" -c 1-8 -t "$FLOOD_TERM" -f "$TMP/" > "$TMP/log" 2>&1 &
pid=$!
sleep 1
if ! kill -0 $pid 2>/dev/null; then
	fail "mmt_sec_standalone -c 1-8 on the flood: instance already exited, SIGTERM path not exercised"
else
	kill -TERM $pid
	for i in $(seq 10); do
		kill -0 $pid 2>/dev/null || break
		sleep 1
	done
	if kill -0 $pid 2>/dev/null; then
		kill -KILL $pid 2>/dev/null
		fail "mmt_sec_standalone -c 1-8 still running 10 s after SIGTERM"
	else
		wait $pid 2>/dev/null; rc=$?
		if [ $rc -eq 0 ]; then
			echo "  -c 1-8 on the flood stops on SIGTERM (rc=0): OK"
		else
			fail "mmt_sec_standalone -c 1-8 stops on SIGTERM with rc=$rc, expected 0 (deferred clean exit)"
		fi
	fi
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
