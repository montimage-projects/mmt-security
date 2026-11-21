#!/usr/bin/env bash
# Fails when `make _csv.X` would not run mmt_sec_standalone with the
# environment variables of check/pcap/X.env, as `make _check.X` does: the
# rewritten check/expect/X.csv would then not be the one `make check` expects
# (e.g. 97.98.http2_conn_table needs MMT_SEC_HTTP2_SEED=1).
#
# Each NAME=value of the file (separated by spaces or lines) must be a word of
# the command line that runs mmt_sec_standalone. The script first tests itself
# on a two-line file.
#
# Usage: check/check-csv-env.sh (run by `make check`; it only prints the
# commands of `make -n`, it runs nothing)
set -u
cd "$(dirname "$0")/.."

# missing VARS COMMANDS: print each NAME=value of VARS that is not a word of a
# line of COMMANDS that runs mmt_sec_standalone (double quotes ignored)
missing() {
	local cmds
	cmds=$(printf '%s\n' "$2" | grep mmt_sec_standalone | tr -d '"')
	printf '%s\n' "$1" | tr -s ' \t' '\n\n' | grep -v '^$' | while read -r var; do
		printf '%s\n' "$cmds" | tr -s ' \t' '\n\n' | grep -qxF -- "$var" || printf '%s\n' "$var"
	done
}

self_test() {
	local vars cmd out
	vars=$(printf 'A_SEED=1\nA_CONNECTIONS=128')
	cmd='bash -c "A_SEED=1  ./mmt_sec_standalone -t x.pcap -f /tmp/"'
	out=$(missing "$vars" "$cmd")
	[ "$out" = "A_CONNECTIONS=128" ] || { echo "  => self-test: a missing 2nd line is not found (got '$out')"; return 1; }
	cmd='bash -c "A_SEED=12 A_CONNECTIONS=128 ./mmt_sec_standalone -t x.pcap -f /tmp/"'
	out=$(missing "$vars" "$cmd")
	[ "$out" = "A_SEED=1" ] || { echo "  => self-test: A_SEED=12 is taken for A_SEED=1 (got '$out')"; return 1; }
	cmd='bash -c "A_SEED=1 A_CONNECTIONS=128 ./mmt_sec_standalone -t x.pcap -f /tmp/"'
	out=$(missing "$vars" "$cmd")
	[ -z "$out" ] || { echo "  => self-test: a complete command is reported (got '$out')"; return 1; }
	out=$(missing "$vars" 'A_SEED=1 A_CONNECTIONS=128 ./other')
	[ -n "$out" ] || { echo "  => self-test: a command that does not run mmt_sec_standalone is accepted"; return 1; }
}

self_test || exit 1
status=0
for env in check/pcap/*.env; do
	[ -e "$env" ] || continue
	name=$(basename "$env" .env)
	vars=$(cat "$env")
	for target in _check _csv; do
		out=$(missing "$vars" "$(make -n "$target.$name" 2>/dev/null)")
		if [ -n "$out" ]; then
			echo "  => make $target.$name does not run mmt_sec_standalone with" $out "(from $env)"
			status=1
		fi
	done
done
[ $status -eq 0 ] && echo "make _check.X and make _csv.X both use check/pcap/X.env"
exit $status
