#!/usr/bin/env bash
# UndefinedBehaviorSanitizer sweep of mmt_sec_standalone for misaligned
# accesses (fork #66), run by `make check` as target check-ubsan-align.
#
# The elements of a message_t are embedded in msg->_data, each headed by an
# mmt_memory_t. They used to be packed at a stride of
# data_length + sizeof(mmt_memory_t) + 1, so every element after the first
# could sit at arbitrary alignment and each typed read through it was a
# misaligned access: mmt_mem_cmp / mmt_mem_size / mmt_mem_revert
# (src/lib/mmt_alloc.h), the key fold of rule_verif_engine.c, and the
# generated rules' *(const double *) and proto_hierarchy_t loads.
#
# It builds the engine and the rules with `make UBSAN=1` in a scratch copy
# of the tree (the checked build outputs are untouched; the rules are
# instrumented via RULE_GCC_ARGS), then runs every check/pcap twice: once
# single-threaded (thread-nb 0, the default), once in SMP mode (-c 1-8).
# Each pcap's .opt options and .env environment apply as in `make check`.
# A run must produce no "misaligned" / "byte alignment" runtime error; the
# script fails and dumps the reports otherwise.
#
# The pcaps are swept in parallel, one job per pcap running both legs into
# its own logs; the jobs are bounded by UBSAN_JOBS (default: half the
# cores).
#
# A last leg exercises the other packed-storage reader: mmt_sec_server
# parses each wire report in place (the timestamp at index 1, each element
# data at an arbitrary offset). check/ubsan_server_feed.c streams reports
# that put a scalar of every size of dpi_message_set_dpi_data at an odd
# offset and carry the attributes of rule 13, so the run must produce no
# UBSan report and at least one alert.
#
# Usage: check/check-ubsan-align.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
runs=0

fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing library and generated rules for misaligned accesses under UBSan"

#probe that this platform can compile and run a UBSan binary at all, before
#paying for the build (same skip-not-fail platform check as check-tsan.sh)
printf 'int main(void){return 0;}\n' > "$TMP/probe.c"
if ! gcc -fsanitize=undefined "$TMP/probe.c" -o "$TMP/probe" > "$TMP/probe.log" 2>&1 \
	|| ! "$TMP/probe" >> "$TMP/probe.log" 2>&1; then
	echo "  => SKIPPED: this platform cannot run a UBSan build:"
	head -3 "$TMP/probe.log"
	exit 0
fi

B="$TMP/build"
mkdir "$B"
for d in Makefile src rules check mmt-security.conf; do
	cp -a "$d" "$B/" || exit 1
done
#do not keep any prebuilt output of the source dir: stale .o or binaries
#(built without UBSan, or older than the sources) must not be reused
find "$B" -name "*.o" -delete
rm -f "$B"/mmt_sec_standalone "$B"/mmt_sec_server "$B"/compile_rule \
	"$B"/rule_info "$B"/rules/*.so

( cd "$B" && make -j1 UBSAN=1 _prepare sec_server ) > "$TMP/make.log" 2>&1 || {
	cat "$TMP/make.log"; fail "UBSan build failed (make UBSAN=1 _prepare sec_server)"; exit 1
}

#do not stop at the first report of a run: every access of a pcap counts
export UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=0"

# the sweep runs in parallel, one job per pcap, bounded by UBSAN_JOBS
# (default: half the cores) - each job does both legs of its pcap
# sequentially into its own logs in $LOGS, so a report is always attributed
# to the pcap and the leg that produced it
JOBS=${UBSAN_JOBS:-$(( $(nproc 2>/dev/null || echo 2) / 2 ))}
[ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1
LOGS="$TMP/logs"; mkdir -p "$LOGS"
export B ROOT LOGS

sweep_one(){ # pcap
	local pcap=$1 name env opt leg seg rc n
	name=$(basename "$pcap" .pcap)
	env=$(cat "${pcap%.pcap}.env" 2>/dev/null)
	opt=$(cat "${pcap%.pcap}.opt" 2>/dev/null)
	mkdir -p "$LOGS/out.$name"
	for leg in t0 smp; do
		seg="$LOGS/$name.$leg.log"
		if [ "$leg" = smp ]; then set -- -c 1-8; else set --; fi
		( cd "$B" && timeout -s KILL 300 env $env ./mmt_sec_standalone "$@" $opt \
			-t "$ROOT/$pcap" -f "$LOGS/out.$name/" ) > "$seg" 2>&1
		rc=$?
		n=$(grep -c "misaligned\|byte alignment\|insufficient alignment" "$seg")
		if [ "$n" -gt 0 ]; then
			echo "ubsan=$n $leg" >> "$LOGS/$name.fail"
		elif [ "$rc" -ne 0 ]; then
			echo "rc=$rc $leg" >> "$LOGS/$name.fail"
		fi
	done
}
export -f sweep_one

printf '%s\n' check/pcap/*.pcap | xargs -P "$JOBS" -n1 bash -c 'sweep_one "$1"' _

# report, in the deterministic order of the pcap listing
for pcap in check/pcap/*.pcap; do
	name=$(basename "$pcap" .pcap)
	if [ ! -f "$LOGS/$name.t0.log" ] || [ ! -f "$LOGS/$name.smp.log" ]; then
		fail "no result for $pcap (its sweep job did not run?)"
		continue
	fi
	runs=$((runs + 2))
	if [ ! -f "$LOGS/$name.fail" ]; then
		echo "  t0 and -c 1-8 on $name: 0 reports"
		continue
	fi
	while read -r kind leg; do
		if [ "$leg" = smp ]; then args="-c 1-8"; else args=""; fi
		case "$kind" in
		ubsan=*)
			fail "UBSan misaligned reports (${kind#ubsan=}) on $pcap${args:+ ($args)}"
			grep -m 10 "misaligned\|byte alignment\|insufficient alignment" "$LOGS/$name.$leg.log"
			;;
		rc=*)
			fail "mmt_sec_standalone $args exits ${kind#rc=} on $pcap under UBSan"
			tail -20 "$LOGS/$name.$leg.log"
			;;
		esac
	done < "$LOGS/$name.fail"
done

# mmt_sec_server's wire path: the same packed-buffer parse, fed by
# check/ubsan_server_feed.c over a unix socket (no port to clash). The
# reports put a scalar of every size at an odd offset and carry rule 13's
# attributes, so a run must produce no UBSan report and at least one alert.
echo
echo "Testing mmt_sec_server's wire report parsing under UBSan"
runs=$((runs + 1))
if ! gcc -O2 -o "$TMP/feed" check/ubsan_server_feed.c 2> "$TMP/feed-build.log"; then
	cat "$TMP/feed-build.log"
	fail "cannot build check/ubsan_server_feed.c"
else
	mkdir -p "$LOGS/server-out"
	# exec keeps $! the pid of mmt_sec_server itself (for the TERM below)
	( cd "$B" && exec ./mmt_sec_server -p "$TMP/sec.sock" \
		-f "$LOGS/server-out/" ) > "$LOGS/server.log" 2>&1 &
	spid=$!
	# reports then disconnect: the forked child exits when its recv ends
	"$TMP/feed" "$TMP/sec.sock" 50 > "$LOGS/feed.log" 2>&1
	feed_rc=$?
	# the feed can finish before the server accepts: first wait for the
	# forked child to appear (ppid == $spid in /proc/*/stat), then for it
	# to drain and exit; both bounded
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
		ls "$LOGS"/server-out/*.csv > /dev/null 2>&1 && break
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

	n=$(grep -c "misaligned\|byte alignment\|insufficient alignment" "$LOGS/server.log")
	if [ "$n" -gt 0 ]; then
		fail "UBSan misaligned reports ($n) on mmt_sec_server's wire path"
		grep -m 10 "misaligned\|byte alignment\|insufficient alignment" "$LOGS/server.log"
	elif [ $feed_rc -ne 0 ]; then
		fail "ubsan_server_feed exits $feed_rc"
		cat "$LOGS/feed.log"
	elif [ $src -ne 0 ]; then
		fail "mmt_sec_server exits $src under UBSan"
		tail -20 "$LOGS/server.log"
	else
		alerts=$(cat "$LOGS"/server-out/*.csv 2>/dev/null | wc -l)
		if [ "$alerts" -eq 0 ]; then
			fail "mmt_sec_server produced no alert: the feed did not drive the wire path to a verdict"
			tail -20 "$LOGS/server.log"
		else
			echo "  server leg: 0 reports, $alerts alert(s) written to the verdict CSV"
		fi
	fi
fi

if [ "$status" -eq 0 ]; then
	echo "  => OK: 0 UBSan misaligned report(s) in $runs run(s)"
fi
exit $status
