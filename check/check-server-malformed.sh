#!/usr/bin/env bash
# mmt_sec_server must validate each report it receives on the wire: the
# announced length of the report and of every element in it against the
# bytes that are actually received. This leg builds the engine and the
# rules with `make ASAN=1` in a scratch copy of the tree (the checked
# build outputs are untouched; the rules are instrumented via
# RULE_GCC_ARGS), then feeds a unix-domain connection of the server with
# check/malformed_server_feed.c: reports whose announced lengths do not
# match their data, each followed by a valid report - on the same
# connection when the wire stays synchronized, on a fresh one otherwise.
#
# Every valid report carries the attributes of rule 13, so a run must
# produce one alert per valid report, no AddressSanitizer report and no
# exit of the serving child on client input.
#
# Usage: check/check-server-malformed.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0

fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing mmt_sec_server's report length validation under ASan"

#probe that this platform can compile and run an ASan binary at all, before
#paying for the build (same skip-not-fail platform check as check-ubsan-align.sh)
printf 'int main(void){return 0;}\n' > "$TMP/probe.c"
if ! gcc -fsanitize=address "$TMP/probe.c" -o "$TMP/probe" > "$TMP/probe.log" 2>&1 \
	|| ! ASAN_OPTIONS=detect_leaks=0 "$TMP/probe" >> "$TMP/probe.log" 2>&1; then
	echo "  => SKIPPED: this platform cannot run an ASan build:"
	head -3 "$TMP/probe.log"
	exit 0
fi

B="$TMP/build"
mkdir "$B"
for d in Makefile src rules check mmt-security.conf; do
	cp -a "$d" "$B/" || exit 1
done
#do not keep any prebuilt output of the source dir: stale .o or binaries
#(built without ASan, or older than the sources) must not be reused
find "$B" -name "*.o" -delete
rm -f "$B"/mmt_sec_standalone "$B"/mmt_sec_server "$B"/compile_rule \
	"$B"/rule_info "$B"/rules/*.so

( cd "$B" && make -j1 ASAN=1 _prepare sec_server ) > "$TMP/make.log" 2>&1 || {
	cat "$TMP/make.log"; fail "ASan build failed (make ASAN=1 _prepare sec_server)"; exit 1
}

if ! gcc -O2 -o "$TMP/feed" check/malformed_server_feed.c 2> "$TMP/feed-build.log"; then
	cat "$TMP/feed-build.log"
	fail "cannot build check/malformed_server_feed.c"
	exit 1
fi

mkdir -p "$TMP/server-out"
# exec keeps $! the pid of mmt_sec_server itself (for the TERM below)
( cd "$B" && exec env ASAN_OPTIONS=detect_leaks=0 ./mmt_sec_server -p "$TMP/sec.sock" \
	-f "$TMP/server-out/" ) > "$TMP/server.log" 2>&1 &
spid=$!
# the feed can finish before the server accepts: first wait for the
# forked child to appear (ppid == $spid in /proc/*/stat), then for it
# to drain and exit; both bounded
"$TMP/feed" "$TMP/sec.sock" > "$TMP/feed.log" 2>&1
feed_rc=$?
_cpid(){
	cpid=
	for f in /proc/[0-9]*/stat; do
		rest=$(sed 's/^.*) //' "$f" 2>/dev/null)
		set -- $rest
		[ "${2:-}" = "$spid" ] && { cpid=${f#/proc/}; cpid=${cpid%/stat}; break; }
	done
}
cpid=
for i in $(seq 50); do
	_cpid
	[ -n "$cpid" ] && break
	ls "$TMP"/server-out/*.csv > /dev/null 2>&1 && break
	sleep 0.1
done
for i in $(seq 150); do
	_cpid
	[ -z "$cpid" ] && break
	sleep 0.1
done
# a child that outlives the bound is stopped rather than left behind
if [ -n "$cpid" ]; then
	kill -TERM $cpid 2>/dev/null; sleep 1; kill -KILL $cpid 2>/dev/null
fi
kill -TERM $spid 2>/dev/null
for i in $(seq 150); do
	kill -0 $spid 2>/dev/null || break
	sleep 0.1
done
kill -KILL $spid 2>/dev/null
wait $spid 2>/dev/null
src=$?

n=$(grep -c "AddressSanitizer\|runtime error" "$TMP/server.log")
if [ "$n" -gt 0 ]; then
	fail "sanitizer reports ($n) on mmt_sec_server's wire path"
	grep -m 10 "AddressSanitizer\|runtime error" "$TMP/server.log"
elif grep -q "HALT_SEC" "$TMP/server.log"; then
	fail "mmt_sec_server stopped on client input"
	grep -m 5 "HALT_SEC" "$TMP/server.log"
elif [ $feed_rc -ne 0 ]; then
	fail "malformed_server_feed exits $feed_rc"
	cat "$TMP/feed.log"
elif [ $src -ne 0 ]; then
	fail "mmt_sec_server exits $src under ASan"
	tail -20 "$TMP/server.log"
else
	# one alert per valid report: the feed drives 8 of them
	alerts=$(cat "$TMP"/server-out/*.csv 2>/dev/null | wc -l)
	if [ "$alerts" -ne 8 ]; then
		fail "mmt_sec_server produced $alerts alert(s), expected 8: the server did not keep serving after a malformed report"
		tail -20 "$TMP/server.log"
	else
		echo "  server leg: 0 reports, $alerts alert(s) written to the verdict CSV"
	fi
fi

if [ "$status" -eq 0 ]; then
	echo "  => OK"
fi
exit $status
