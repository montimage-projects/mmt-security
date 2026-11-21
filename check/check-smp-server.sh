#!/usr/bin/env bash
# Checks of the SMP mode of mmt_sec_server (Montimage fork #31, E3), run by
# `make check`: each connection is served by a forked child running its own
# SMP workers (`-n`), and a SIGTERM used to run the whole termination -
# including mmt_smp_sec_process(NULL) and pthread_join - inside the signal
# handler, which deadlocked whenever the signal landed on a busy thread.
# The parent and a child, signalled mid-stream, must now stop within a bound,
# and the parent exits 0 (deferred clean shutdown) instead of the signal's
# number as before.
#
# Usage: check/check-smp-server.sh [path/to/mmt_sec_server]
set -u
cd "$(dirname "$0")/.."
SERVER=$(realpath "${1:-./mmt_sec_server}")
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing mmt_sec_server in SMP mode (-n 8 -c 1-8): SIGTERM to a child and to the parent"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}/opt/mmt/dpi/lib"

if ! gcc -O2 -o "$TMP/feed" check/smp_server_feed.c; then
	fail "cannot compile check/smp_server_feed.c"
	echo "  => FAILED"
	exit 1
fi

# wait until $1 is gone or BOUND s elapsed; rc 0 = gone, 1 = still running
gone(){ # pid bound
	for i in $(seq "$2"); do
		kill -0 "$1" 2>/dev/null || return 0
		sleep 1
	done
	! kill -0 "$1" 2>/dev/null
}

# the forked child of $1 (the process whose ppid it is), empty if none yet
child_of(){
	local want=$1 f rest
	for f in /proc/[0-9]*/stat; do
		rest=$(sed 's/^.*) //' "$f" 2>/dev/null) # "S ppid ...": comm may hold ' '
		set -- $rest
		[ "${2:-}" = "$want" ] && { f=${f#/proc/}; echo "${f%/stat}"; return; }
	done
}

# one registered proto.att of a rule (e.g. "tcp.flags (354.6)" from rule_info,
# passed to the feed as two arguments): the reports then reach a worker's ring
# instead of being dropped at the routing; without one the feed falls back to
# empty reports
pair=$(./rule_info rules/56.syn_flooding.so 2>/dev/null | grep -oE '\([0-9]+\.[0-9]+\)' | tail -1 | tr -d '()' | tr . ' ')

PORT=50087
"$SERVER" -p $PORT -n 8 -c 1-8 > "$TMP/log" 2>&1 &
spid=$!

# one client streams reports in the background (back-to-back: the child's
# read/parse loop stays busy so the signal lands mid-processing): a forked
# child serves it
"$TMP/feed" $PORT 100000 0 $pair > "$TMP/feed.log" 2>&1 &
fpid=$!

# the forked child serving the connection (the feed retries the connect until
# the server listens, so wait for it up to 10 s)
cpid=
for i in $(seq 100); do
	cpid=$(child_of $spid)
	[ -n "$cpid" ] && break
	kill -0 $fpid 2>/dev/null || break
	sleep 0.1
done

if [ -z "$cpid" ]; then
	fail "no forked child of mmt_sec_server found for the connection"
elif ! kill -0 $cpid 2>/dev/null; then
	fail "the forked child already exited, SIGTERM path not exercised"
else
	kill -TERM $cpid
	if gone $cpid 15; then
		echo "  child $cpid mid-stream stops on SIGTERM: OK"
	else
		kill -KILL $cpid 2>/dev/null
		fail "mmt_sec_server child still running 15 s after SIGTERM"
	fi
fi

if ! kill -0 $spid 2>/dev/null; then
	fail "mmt_sec_server parent already exited, SIGTERM path not exercised"
else
	kill -TERM $spid
	if gone $spid 15; then
		wait $spid 2>/dev/null; rc=$?
		if [ $rc -eq 0 ]; then
			echo "  parent $spid stops on SIGTERM (rc=0): OK"
		else
			fail "mmt_sec_server parent stops on SIGTERM with rc=$rc, expected 0 (deferred clean exit)"
		fi
	else
		kill -KILL $spid 2>/dev/null
		fail "mmt_sec_server parent still running 15 s after SIGTERM"
	fi
fi

kill $fpid 2>/dev/null
wait $fpid 2>/dev/null
wait $spid 2>/dev/null

[ $status -eq 0 ] && echo "  => OK"
exit $status
