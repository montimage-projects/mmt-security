#!/bin/bash
# Rules 97 and 98 keep a connection table per verification thread. on_unload
# runs once, in the main thread, and must free the table of every thread.
# This check runs them with 2 verification threads (-c) under valgrind and
# fails on a definite leak.
#
# usage: make check-valgrind, or check/h2_thread_leak.sh (after
#        `make standalone sample_rules`); needs valgrind
set -u
cd "$(dirname "$0")/.." || exit 1
command -v valgrind >/dev/null || { echo "valgrind not found"; exit 2; }
ret=0
for p in check/pcap/97.http2_hpack_bomb.pcap check/pcap/98.http2_fuzzing.pcap; do
	d=$(mktemp -d)
	valgrind --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite \
		--error-exitcode=9 ./mmt_sec_standalone -c 1-2 -x 1-96,99-100000 -t "$p" -f "$d/" > "$d/valgrind.log" 2>&1
	rc=$?
	if [ $rc -eq 0 ]; then
		echo "  => OK: no leak, $p"
	else
		grep -A6 "definitely lost in" "$d/valgrind.log"
		echo "  => FAILED (valgrind exit $rc): $p"
		ret=1
	fi
	rm -rf "$d"
done
exit $ret
