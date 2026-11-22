#!/usr/bin/env bash
# ThreadSanitizer sweep of the SMP message hand-off of mmt_sec_standalone
# (fork #45), run by `make check` as target check-tsan.
#
# It builds the engine and the rules with `make TSAN=1` in a scratch copy of
# the tree (the checked build outputs are untouched), then runs `-c 1-8` on
# every check/pcap twice: once with all rules loaded, once with rule 54 alone
# (-x 1-53,55-99999). Each pcap's .opt options and .env environment apply as
# in `make check`. A run must report no race; the script fails and dumps the
# reports otherwise. Orderings that are real but invisible to TSan (the SPSC
# ring's acquire/release) are suppressed, narrowly and with the reason, in
# check/tsan_suppressions.txt.
#
# The pcaps are swept in parallel, one job per pcap running both legs into
# its own logs; the jobs are bounded by TSAN_JOBS (default: half the cores).
#
# Usage: check/check-tsan.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
runs=0

fail(){ echo "  => FAILED: $*"; status=1; }

SUPP="$ROOT/check/tsan_suppressions.txt"
if [ ! -f "$SUPP" ]; then
	echo "missing TSan suppressions file: $SUPP"
	exit 1
fi

echo
echo "Testing mmt_sec_standalone in SMP mode (-c) under ThreadSanitizer"

#probe that this platform can compile and run a TSan binary at all, before
#paying for the build: some compiler/kernel combinations cannot (e.g. GCC 13
#on kernels that moved the VMA area: "FATAL: ThreadSanitizer: unexpected
#memory mapping"), then the sweep is skipped, not failed - it is a platform
#limitation. The engine build itself runs a TSan binary (compile_rule), so
#the probe must precede it.
printf 'int main(void){return 0;}\n' > "$TMP/probe.c"
if ! gcc -fsanitize=thread "$TMP/probe.c" -o "$TMP/probe" > "$TMP/probe.log" 2>&1 \
	|| ! "$TMP/probe" >> "$TMP/probe.log" 2>&1; then
	echo "  => SKIPPED: this platform cannot run a TSan build:"
	head -3 "$TMP/probe.log"
	exit 0
fi

B="$TMP/build"
mkdir "$B"
for d in Makefile src rules check mmt-security.conf; do
	cp -a "$d" "$B/" || exit 1
done
#do not keep any prebuilt output of the source dir: stale .o or binaries
#(built without TSan, or older than the sources) must not be reused
find "$B" -name "*.o" -delete
rm -f "$B"/mmt_sec_standalone "$B"/mmt_sec_server "$B"/compile_rule \
	"$B"/rule_info "$B"/rules/*.so

#the probe is a smaller binary than compile_rule/the engine: it can pass
#where they still hit the mapping limit inside the build, which shows up as
#a FATAL from a TSan tool (same skip-not-fail platform limitation)
( cd "$B" && make -j1 TSAN=1 _prepare ) > "$TMP/make.log" 2>&1 || {
	if grep -q "ThreadSanitizer: unexpected memory mapping" "$TMP/make.log"; then
		echo "  => SKIPPED: this platform cannot run a TSan build:"
		grep -m1 "unexpected memory mapping" "$TMP/make.log"
		exit 0
	fi
	cat "$TMP/make.log"; fail "TSan build failed (make TSAN=1 _prepare)"; exit 1
}

#the built binary gets a wider memory mapping than the probe above: probe it
#too, same skip-not-fail platform limitation if it cannot run
if ! ( cd "$B" && TSAN_OPTIONS="suppressions=$SUPP" timeout -s KILL 60 \
		./mmt_sec_standalone -l ) > "$TMP/probe.log" 2>&1; then
	echo "  => SKIPPED: this platform cannot run the TSan build:"
	head -3 "$TMP/probe.log"
	exit 0
fi

export TSAN_OPTIONS="suppressions=$SUPP:exitcode=66"

# the sweep runs in parallel, one job per pcap, bounded by TSAN_JOBS
# (default: half the cores) - each job does both legs of its pcap
# sequentially into its own logs in $LOGS, so a report is always attributed
# to the pcap and the leg that produced it
JOBS=${TSAN_JOBS:-$(( $(nproc 2>/dev/null || echo 2) / 2 ))}
[ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1
LOGS="$TMP/logs"; mkdir -p "$LOGS"
export B ROOT LOGS

sweep_one(){ # pcap
	local pcap=$1 name env opt leg seg rc
	name=$(basename "$pcap" .pcap)
	env=$(cat "${pcap%.pcap}.env" 2>/dev/null)
	opt=$(cat "${pcap%.pcap}.opt" 2>/dev/null)
	mkdir -p "$LOGS/out.$name"
	for leg in all r54; do
		seg="$LOGS/$name.$leg.log"
		[ "$leg" = r54 ] && set -- -x 1-53,55-99999 || set --
		( cd "$B" && timeout -s KILL 300 env $env ./mmt_sec_standalone -c 1-8 $opt "$@" \
			-t "$ROOT/$pcap" -f "$LOGS/out.$name/" ) > "$seg" 2>&1
		rc=$?
		if grep -q "WARNING: ThreadSanitizer" "$seg"; then
			echo "tsan $leg" >> "$LOGS/$name.fail"
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
	if [ ! -f "$LOGS/$name.all.log" ] || [ ! -f "$LOGS/$name.r54.log" ]; then
		fail "no result for $pcap (its sweep job did not run?)"
		continue
	fi
	runs=$((runs + 2))
	if [ ! -f "$LOGS/$name.fail" ]; then
		echo "  -c 1-8 on $name (all rules, rule 54 alone): 0 reports"
		continue
	fi
	while read -r kind leg; do
		if [ "$leg" = r54 ]; then args="-x 1-53,55-99999"; else args=""; fi
		if [ "$kind" = tsan ]; then
			fail "ThreadSanitizer reports on $pcap${args:+ ($args)}"
			cat "$LOGS/$name.$leg.log"
		else
			fail "mmt_sec_standalone -c 1-8 $args exits ${kind#rc=} on $pcap under TSan"
			tail -20 "$LOGS/$name.$leg.log"
		fi
	done < "$LOGS/$name.fail"
done

if [ "$status" -eq 0 ]; then
	echo "  => OK: 0 ThreadSanitizer report(s) in $runs run(s) of -c 1-8"
fi
exit $status
