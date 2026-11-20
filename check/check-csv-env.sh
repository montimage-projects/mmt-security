#!/usr/bin/env bash
# Fails when `make _csv.X` would not run mmt_sec_standalone with the
# environment variables of check/pcap/X.env, as `make _check.X` does: the
# rewritten check/expect/X.csv would then not be the one `make check` expects
# (e.g. 97.98.http2_conn_table needs MMT_SEC_HTTP2_SEED=1).
#
# Usage: check/check-csv-env.sh (run by `make check`; it only prints the
# commands of `make -n`, it runs nothing)
set -u
cd "$(dirname "$0")/.."
status=0
for env in check/pcap/*.env; do
	[ -e "$env" ] || continue
	name=$(basename "$env" .env)
	vars=$(cat "$env")
	for target in _check _csv; do
		if ! make -n "$target.$name" 2>/dev/null | grep -F -- "$vars" | grep -q mmt_sec_standalone; then
			echo "  => make $target.$name does not run mmt_sec_standalone with $vars (from $env)"
			status=1
		fi
	done
done
[ $status -eq 0 ] && echo "make _check.X and make _csv.X both use check/pcap/X.env"
exit $status
