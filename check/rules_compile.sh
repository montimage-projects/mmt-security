#!/bin/bash
# Negative tests for compile_rule (Montimage/mmt-security#52).
# Each check/rules_compile/*.xml starts with two comments:
#   <!-- expect-exit: N -->        exit code compile_rule must return
#   <!-- expect-output: TEXT -->   text its output must contain
# A crash (exit code >= 128) always fails.
# Usage: check/rules_compile.sh ./compile_rule
COMPILE_RULE=${1:-./compile_rule}
DIR=$(dirname "$0")/rules_compile
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0
for xml in "$DIR"/*.xml; do
	name=$(basename "$xml" .xml)
	exp_exit=$(sed -n 's/^<!-- expect-exit: \(.*\) -->$/\1/p' "$xml")
	exp_out=$(sed -n 's/^<!-- expect-output: \(.*\) -->$/\1/p' "$xml")
	"$COMPILE_RULE" "$TMP/$name.so" "$xml" > "$TMP/$name.log" 2>&1
	rc=$?
	if [ "$rc" -ne "$exp_exit" ] || ! grep -qF -- "$exp_out" "$TMP/$name.log"; then
		echo "  FAIL $name: exit $rc (expected $exp_exit), output must contain: $exp_out"
		sed 's/^/    | /' "$TMP/$name.log"
		fail=1
	else
		echo "  ok   $name (exit $rc)"
	fi
done
exit $fail
