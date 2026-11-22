#!/usr/bin/env bash
# Checks the exit status of the tools' help and usage errors (fork issue #47),
# run by `make check`: -h and --help must exit 0 for mmt_sec_standalone,
# mmt_sec_server, rule_info and compile_rule; a bad option must exit 1.
#
# Usage: check/check-help.sh [mmt_sec_standalone mmt_sec_server rule_info compile_rule]
set -u
cd "$(dirname "$0")/.."
[ $# -eq 0 ] && set -- ./mmt_sec_standalone ./mmt_sec_server ./rule_info ./compile_rule
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

for tool in "$@"; do
	for o in -h --help; do
		"$tool" $o >/dev/null 2>&1 || fail "$tool $o exits $?"
	done
	for o in -Z --bogus; do
		"$tool" $o >/dev/null 2>&1 && fail "$tool $o exits 0 (a bad option must exit 1)"
	done
done

[ $status -eq 0 ] && echo "  => OK: -h/--help exit 0, a bad option exits 1, for all 4 tools"
exit $status
