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
#     count SYNs to one destination at once (check/syn_flood_threads.c);
#  4. rules 56 and 57 draw their hash seeds per process, MMT_SEC_SYN_FLOOD_HASH_SEED
#     sets them (check/syn_flood_seed.c) and is logged with a warning, and with
#     the unseeded hash (seed 0), the 8 ports of
#     check/pcap/57.syn_flood_crafted_ports.pcap that share the victim's home
#     slot do not hide the victim;
#  5. rule 56 gives no false alert when more than 65536 handshakes are pending
#     at once and all complete, and reports only on a packet to the victim
#     server port (check/syn_flood_rule56.c);
#  6. the servers of check/pcap/56.crafted_servers_attack.pcap, crafted for the
#     unseeded hash, still hide the victim from rule 56 with seed 0: the pcap
#     keeps proving that the seed is what defends (make check runs it with
#     another seed, from its .env file, and expects the 3 alerts of the victim).
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

perl -0777 -ne 'print $1 if /<!\[CDATA\[(.*?)\]\]>/s' rules/56.syn_flooding.xml > "$TMP/rule56.c"
for rule in 56 57; do
	echo
	echo "Testing rule $rule's hash seed"
	seedvar=em_syn_flood_seed
	[ $rule = 56 ] && seedvar=em_syn56_seed
	if gcc -O2 -pthread -DRULE_C="\"$TMP/rule$rule.c\"" -DSEED=$seedvar -o "$TMP/seed" check/syn_flood_seed.c; then
		s1=$("$TMP/seed" 2>/dev/null); s2=$("$TMP/seed" 2>/dev/null)
		s57=$(MMT_SEC_SYN_FLOOD_HASH_SEED=57 "$TMP/seed" 2>/dev/null)
		bad=$(MMT_SEC_SYN_FLOOD_HASH_SEED=-1 "$TMP/seed" 2>&1 >/dev/null | grep -c "WARN Rule $rule: ignored MMT_SEC_SYN_FLOOD_HASH_SEED")
		echo "  two processes: seeds $s1 and $s2; MMT_SEC_SYN_FLOOD_HASH_SEED=57: $s57; =-1: $bad warning(s)"
		[ -n "$s1" ] && [ "$s1" != "$s2" ] || fail "rule $rule does not draw a new hash seed per process"
		[ "$s57" = 57 ] || fail "rule $rule: MMT_SEC_SYN_FLOOD_HASH_SEED=57 gives the seed $s57"
		[ "$bad" = 1 ] || fail "rule $rule: MMT_SEC_SYN_FLOOD_HASH_SEED=-1 gives $bad warnings, expected 1"
	else
		fail "cannot compile check/syn_flood_seed.c for rule $rule"
	fi
done

echo
echo "Testing that the hash seed override is logged as a warning"
# rules 56 and 57 together on a pcap with a SYN flood, the override set
rm -rf "$TMP/out"; mkdir "$TMP/out"
MMT_SEC_SYN_FLOOD_HASH_SEED=0 "$STANDALONE" -x 1-55,58-99999 -t check/pcap/56.syn_flood_rst_ack.pcap -f "$TMP/out/" > "$TMP/log" 2>&1
for rule in 56 57; do
	w=$(grep -c "WARN.*Rule $rule: hash seed set by MMT_SEC_SYN_FLOOD_HASH_SEED" "$TMP/log")
	echo "  rule $rule: $w warning(s)"
	[ "$w" = 1 ] || fail "rule $rule does not log MMT_SEC_SYN_FLOOD_HASH_SEED=0 as a warning"
done

echo
echo "Testing rule 57 against 8 ports crafted to share the victim's home slot (unseeded hash)"
PCAP57C=check/pcap/57.syn_flood_crafted_ports.pcap
n=$(alerts 57 "$PCAP57C" MMT_SEC_SYN_FLOOD_HASH_SEED=0)
v=$(cat "$TMP"/out/*.csv 2>/dev/null | grep -c '^[^,]*,[^,]*,[^,]*,[^,]*,57,.*"ip.dst","192.168.1.10"\],\["tcp.dest_port",80\]')
echo "  MMT_SEC_SYN_FLOOD_HASH_SEED=0: $n alert(s), $v for the victim 192.168.1.10:80"
[ "$n" = 2 ] || fail "rule 57 gives $n alerts on $PCAP57C with the unseeded hash, expected 2"
[ "$v" = 1 ] || fail "rule 57 does not report the victim 192.168.1.10:80 of $PCAP57C with the unseeded hash"

echo
echo "Testing rule 56 against servers crafted to share the victim's slots (unseeded hash)"
PCAP56C=check/pcap/56.crafted_servers_attack.pcap
n=$(alerts 56 "$PCAP56C" MMT_SEC_SYN_FLOOD_HASH_SEED=0)
echo "  MMT_SEC_SYN_FLOOD_HASH_SEED=0: $n alert(s) (make check expects 3 with the seed of its .env file)"
[ "$n" = 0 ] || fail "rule 56 gives $n alerts on $PCAP56C with the unseeded hash, expected 0: the pcap no longer targets the unseeded hash"

echo
echo "Testing rule 56's C: more than 65536 pending handshakes, side of the victim"
if gcc -O2 -pthread -DRULE_C="\"$TMP/rule56.c\"" -o "$TMP/rule56" check/syn_flood_rule56.c; then
	"$TMP/rule56" || fail "rule 56 gave a false alert when its FIFO was full, missed the control flood, or reported on a packet from the server port"
else
	fail "cannot compile check/syn_flood_rule56.c"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
