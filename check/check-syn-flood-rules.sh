#!/usr/bin/env bash
# Checks of the SYN flood rules 56 and 57 that a pcap and its expected alerts
# cannot express (run by `make check`):
#  1. rule 57 reads MMT_SEC_SYN_FLOOD_THRESHOLD and MMT_SEC_SYN_FLOOD_WINDOW_MS:
#     a negative, octal, hexadecimal, trailing-garbage, zero or overflowing
#     value gives a warning, and the default (100 SYN within 1000 ms) is used;
#  2. rule 56 keeps a constant cost per packet on a 2000 SYN/s flood
#     (check/pcap/56.57.syn_flood_fast.pcap): its CPU time must stay close to
#     that of rule 57 alone on the same pcap;
#  3. rule 57's counter gives exactly one alert per window when 8 threads
#     count SYNs to one destination at once (check/syn_flood_threads.c).
#
# Usage: check/check-syn-flood-rules.sh [path/to/mmt_sec_standalone]
set -u
cd "$(dirname "$0")/.."
STANDALONE=${1:-./mmt_sec_standalone}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0

fail(){ echo "  => FAILED: $*"; status=1; }

# alerts of one rule on one pcap; stderr of the run in $TMP/log
alerts(){ # rule pcap [VAR=value ...]: prints the number of alerts, or "error"
	local rule=$1 pcap=$2
	shift 2
	rm -rf "$TMP/out"; mkdir "$TMP/out"
	if env "$@" "$STANDALONE" -x "1-$((rule - 1)),$((rule + 1))-99999" -t "$pcap" -f "$TMP/out/" > "$TMP/log" 2>&1; then
		cat "$TMP"/out/*.csv 2>/dev/null | cut -d, -f5 | grep -cx "$rule"
	else
		echo error
	fi
}

echo
echo "Testing rule 57's environment variables"
PCAP57=check/pcap/57.syn_flood_spoofed_oneway.pcap # 300 SYN to one destination within 0.6 s
# variable=value (- for none)  expected alerts  expected warnings
while read -r setting expected warn; do
	[ "$setting" = - ] && setting=
	n=$(alerts 57 "$PCAP57" ${setting:+"$setting"})
	[ "$n" = error ] && cat "$TMP/log"
	w=$(grep -c "WARN.*Rule 57: ignored" "$TMP/log")
	printf "  %-46s %s alert(s), %s warning(s)\n" "${setting:-(none)}" "$n" "$w"
	[ "$n" = "$expected" ] || fail "rule 57 with ${setting:-no variable}: $n alerts, expected $expected"
	[ "$w" = "$warn" ] || fail "rule 57 with ${setting:-no variable}: $w warnings, expected $warn"
done <<'EOF'
- 1 0
MMT_SEC_SYN_FLOOD_THRESHOLD=300 1 0
MMT_SEC_SYN_FLOOD_THRESHOLD=301 0 0
MMT_SEC_SYN_FLOOD_THRESHOLD=-5 1 1
MMT_SEC_SYN_FLOOD_THRESHOLD=010 1 1
MMT_SEC_SYN_FLOOD_THRESHOLD=0x10 1 1
MMT_SEC_SYN_FLOOD_THRESHOLD=50abc 1 1
MMT_SEC_SYN_FLOOD_THRESHOLD=0 1 1
MMT_SEC_SYN_FLOOD_THRESHOLD=18446744073709551616 1 1
MMT_SEC_SYN_FLOOD_WINDOW_MS=10 0 0
MMT_SEC_SYN_FLOOD_WINDOW_MS=-1 1 1
MMT_SEC_SYN_FLOOD_WINDOW_MS=18446744073709552 1 1
MMT_SEC_SYN_FLOOD_WINDOW_MS=3600001 1 1
EOF

echo
echo "Testing rule 56's cost on a 2000 SYN/s flood"
PCAP56=check/pcap/56.57.syn_flood_fast.pcap
TIMEFORMAT='%3U %3S'
cpu(){ # rule: user+sys CPU seconds of one run on $PCAP56
	local t
	t=$( { time timeout 300 "$STANDALONE" -x "1-$(($1 - 1)),$(($1 + 1))-99999" -t "$PCAP56" -f "$TMP/" > /dev/null 2>&1 ; } 2>&1 )
	awk -v t="$t" 'BEGIN{ split(t, a, " "); printf "%.2f", a[1] + a[2] }'
}
base=$(cpu 57)
c56=$(cpu 56)
limit=$(awk -v b="$base" 'BEGIN{ printf "%.2f", 2 * b + 2 }')
echo "  rule 57 alone: ${base} s, rule 56 alone: ${c56} s of CPU (limit: ${limit} s)"
awk -v c="$c56" -v l="$limit" 'BEGIN{ exit !(c <= l) }' || fail "rule 56 takes ${c56} s of CPU on $PCAP56 (limit ${limit} s)"

echo
echo "Testing rule 57's counter with 8 threads"
perl -0777 -ne 'print $1 if /<!\[CDATA\[(.*?)\]\]>/s' rules/57.syn_flood_rate.xml > "$TMP/rule57.c"
if gcc -O2 -pthread -DRULE_C="\"$TMP/rule57.c\"" -o "$TMP/threads" check/syn_flood_threads.c; then
	"$TMP/threads" 2>/dev/null || fail "rule 57 missed or repeated an alert with 8 threads"
else
	fail "cannot compile check/syn_flood_threads.c"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
