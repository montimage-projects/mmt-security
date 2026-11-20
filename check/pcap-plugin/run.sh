#!/usr/bin/env bash
# Runs the OCPP plugin rules 230 and 231 on the synthetic captures of
# check/pcap-plugin/pcap/ (written by gen_ocpp_pcaps.py) and checks the alerts
# against check/pcap-plugin/cases and check/pcap-plugin/expect/.
#
# Needs mmt-security built with the OCPP plugin `ocpp_example` installed in
# MMT-DPI's plugin folder (doc/rule.md, section 7):
#
#     make clean-all && make -j1 && check/pcap-plugin/run.sh
#
# A stock build has no OCPP_EXAMPLE protocol and cannot compile these rules,
# so `make check` does not run this. RULES_XML_DIR (default
# rules/properties_all) is where the two rule XMLs are read from.
set -u
cd "$(dirname "$0")/../.."
here=check/pcap-plugin
xml_dir=${RULES_XML_DIR:-rules/properties_all}
ocpp_rules="230.ocpp_heartbeat_flood 231.ocpp_charging_limit"

die() { echo "run.sh: $*" >&2; exit 2; }

[ -x ./compile_rule ] && [ -x ./mmt_sec_standalone ] || die "build mmt-security first (make -j1)"
grep -q '"OCPP_EXAMPLE"' src/dpi/mmt_dpi.h \
	|| die "src/dpi/mmt_dpi.h has no OCPP_EXAMPLE: install the plugin, then make clean-all && make -j1 (doc/rule.md, section 7)"

tmp=$(mktemp -d)
cleanup() {
	rm -rf "$tmp"
	for r in $ocpp_rules; do rm -f "rules/$r.so"; done
}
trap cleanup EXIT

make --no-print-directory -s sample_rules >/dev/null || die "make sample_rules failed"
for r in $ocpp_rules; do
	./compile_rule "rules/$r.so" "$xml_dir/$r.xml" >"$tmp/compile.log" 2>&1 \
		|| { cat "$tmp/compile.log"; die "cannot compile $xml_dir/$r.xml"; }
done

pass=0 fail=0
while IFS='|' read -r name settings want; do
	name=$(echo "$name" | xargs)
	case "$name" in ''|'#'*) continue ;; esac
	settings=$(echo "$settings" | xargs)
	want=$(echo "$want" | xargs)
	[ "$settings" = "-" ] && settings=""
	pcap="$here/pcap/$name.pcap"
	[ -f "$pcap" ] || die "missing $pcap"

	rm -rf "$tmp/out" && mkdir "$tmp/out"
	# shellcheck disable=SC2086 # settings are NAME=value words
	env $settings ./mmt_sec_standalone -t "$pcap" -f "$tmp/out/" >"$tmp/run.log" 2>&1 \
		|| { cat "$tmp/run.log"; die "mmt_sec_standalone failed on $pcap"; }
	cat "$tmp"/out/*.csv 2>/dev/null | cut -d, -f5- >"$tmp/alerts.csv"

	# alerts per rule id, "230=3 231=1", sorted by rule id
	got=$(cut -d, -f1 "$tmp/alerts.csv" | sort -n | uniq -c | awk '{printf "%s%s=%s", (NR>1?" ":""), $2, $1}')
	norm=$(for w in $want; do echo "$w"; done | grep -v '=0$' | sort -n | paste -sd' ')
	ok=1
	[ "$got" = "$norm" ] || ok=0
	if [ -z "$settings" ] && [ -f "$here/expect/$name.csv" ]; then
		cut -d, -f5- "$here/expect/$name.csv" | diff --ignore-all-space - "$tmp/alerts.csv" >"$tmp/diff" || ok=0
	fi
	label="$name${settings:+ [$settings]}"
	if [ $ok -eq 1 ]; then
		echo "  OK    $label: ${got:-no alert}"
		pass=$((pass + 1))
	else
		echo "  FAIL  $label: got '${got:-no alert}', expected '${norm:-no alert}'"
		[ -s "$tmp/diff" ] && cat "$tmp/diff"
		fail=$((fail + 1))
	fi
done <"$here/cases"

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
