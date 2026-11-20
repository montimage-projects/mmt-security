#!/usr/bin/env bash
# Fails when a rule XML defines (or declares) on_load or on_unload as static.
#
# The engine finds these hooks with dlsym(lib, "on_load") and
# dlsym(lib, "on_unload") (src/lib/plugins_engine.c), which cannot see a
# function with internal linkage, and gen_code.c then generates no exported
# stand-in because it finds the name in the rule's code: a static on_load
# never runs, so the settings it reads are silently ignored.
#
# Usage: check/check-rule-hooks.sh [rule.xml ...]
# (default: rules/*.xml rules/properties_all/*.xml; run by `make check`)
set -u
cd "$(dirname "$0")/.."
[ $# -gt 0 ] || set -- rules/*.xml rules/properties_all/*.xml

status=0
for f in "$@"; do
	# whole file at once: `static void` and `on_load(` may be on two lines
	perl -0777 -ne '
		while (/\bstatic\b[\w\s\*]*?\b(on_load|on_unload)\s*\(/g) {
			my $line = 1 + (substr($_, 0, $-[1]) =~ tr/\n//);
			print "$ARGV:$line: $1 is static: dlsym() cannot find it, remove `static`\n";
			$found = 1;
		}
		END { exit($found ? 1 : 0) }' "$f" || status=1
done
[ $status -eq 0 ] && echo "No rule defines on_load or on_unload as static"
exit $status
