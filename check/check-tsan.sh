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

# one -c 1-8 run of the TSan binary on $pcap, $* extra args (e.g. -x mask);
# the pcap's .env and .opt apply; reports fail the check
run(){ # pcap extra-args...
	local pcap=$1 name env opt rc
	pcap=$1; shift
	name=${pcap%.pcap}
	env=$(cat "$name.env" 2>/dev/null)
	opt=$(cat "$name.opt" 2>/dev/null)
	mkdir -p "$TMP/out"
	rm -f "$TMP"/out/mmt-security*.csv
	( cd "$B" && timeout -s KILL 300 env $env ./mmt_sec_standalone -c 1-8 $opt "$@" \
		-t "$ROOT/$pcap" -f "$TMP/out/" ) > "$TMP/log" 2>&1
	rc=$?
	runs=$((runs + 1))
	if grep -q "WARNING: ThreadSanitizer" "$TMP/log"; then
		fail "ThreadSanitizer reports on $pcap ($*)"
		cat "$TMP/log"
	elif [ "$rc" -ne 0 ]; then
		fail "mmt_sec_standalone -c 1-8 $* exits $rc on $pcap under TSan"
		tail -20 "$TMP/log"
	fi
}

for pcap in check/pcap/*.pcap; do
	name=$(basename "$pcap" .pcap)
	before=$status
	run "$pcap"
	run "$pcap" -x 1-53,55-99999
	if [ "$status" = "$before" ]; then
		echo "  -c 1-8 on $name (all rules, rule 54 alone): 0 reports"
	fi
done

if [ "$status" -eq 0 ]; then
	echo "  => OK: 0 ThreadSanitizer report(s) in $runs run(s) of -c 1-8"
fi
exit $status
