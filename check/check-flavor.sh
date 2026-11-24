#!/usr/bin/env bash
# Build-flavor stamp check (fork #54), run by `make check` as check-flavor.
#
# In a scratch copy of the tree (the checked build outputs are untouched) it
# builds plain, then `make TSAN=1`, then `make ASAN=1` - with no clean and no
# rm of the objects between flavors - and asserts with nm that every object
# linked into mmt_sec_standalone, libmmt_security2 and the rules/*.so carries
# the flavor's marker (__tsan_*, resp. __asan_*), except the documented
# uninstrumented compile_rule objects (*.gen.o, main_gen_plugin.o) and the
# compile_rule binary, which must carry none. The plain leg must carry
# neither marker.
# On a Makefile with no flavor stamp the second build links the previous
# flavor's objects, and this script fails.
#
# After each leg a second `make` of the same flavor must be the pre-stamp
# no-op of a0f63108: only the --refresh-plugin-engine recompile and the
# relinks it triggers - and .build-flavor must not be rewritten. A stamp
# rewritten on every parse (a signature that never matches) shows up here
# as a full rebuild and a newer stamp.
#
# A sanitizer leg is skipped, not failed, on a platform whose toolchain
# cannot compile and link the sanitizer's probe (e.g. gcc without libtsan
# cannot link a TSan binary at all) - the same skip-not-fail platform
# limitation as check-tsan.sh, so `make check` does not regress where it
# passed before the stamp existed.
#
# Usage: check/check-flavor.sh
set -u
cd "$(dirname "$0")/.." || exit 1
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0

fail(){ echo "  => FAILED: $*"; status=1; }

JOBS=${FLAVOR_JOBS:-$(nproc 2>/dev/null || echo 4)}

echo
echo "Testing that switching build flavors relinks no object of another flavor"

B="$TMP/build"
mkdir "$B"
for d in Makefile src rules mmt-security.conf; do
	cp -a "$d" "$B/" || exit 1
done
# stale outputs of the source dir must not leak into the scratch build
find "$B" -name "*.o" -delete
rm -f "$B"/mmt_sec_standalone "$B"/mmt_sec_server "$B"/compile_rule \
	"$B"/rule_info "$B"/rules/*.so

build(){ # leg-name make-args...
	local name=$1; shift
	( cd "$B" && make -j"$JOBS" "$@" lib _prepare sec_server rule_info ) > "$TMP/make.$name.log" 2>&1 || {
		cat "$TMP/make.$name.log"; fail "$name build failed"; exit 1; }
}

# has_marker file marker-regex: exit 0 when the file carries a marker symbol
has_marker(){ nm "$1" 2>/dev/null | grep -q "$2"; }

# the objects the checked artifacts are linked from: the library objects,
# the tool mains, the static-link rule objects (STATIC_LINK only), the
# rules/*.so and the artifacts themselves. Excluded: the compile_rule
# objects (*.gen.o) and src/main_gen_plugin.o, which under ASAN/TSAN are
# not linked into any checked artifact - they may stay at the previous
# flavor - but they must never carry a sanitizer marker either way.
check_tree(){ # marker-regex|none  leg-name
	local re=$1 name=$2 f n=0 missing=0 extra=0
	while IFS= read -r f; do
		n=$((n+1))
		if [ "$re" = none ]; then
			if has_marker "$f" '\(__tsan_\|__asan_\)'; then
				fail "$name: $f carries a sanitizer marker in a plain build"; extra=$((extra+1))
			fi
		elif ! has_marker "$f" "$re"; then
			fail "$name: $f carries no $re (object of another flavor linked)"
			missing=$((missing+1))
		fi
	done < <( { find "$B/src" -name '*.o' ! -name '*.gen.o' ! -name 'main_gen_plugin.o'; \
		find "$B/rules" \( -name '*.o' -o -name '*.so' \); \
		echo "$B/libmmt_security2.a"; echo "$B/libmmt_security2.so"; \
		echo "$B/mmt_sec_standalone"; echo "$B/mmt_sec_server"; \
		echo "$B/rule_info"; } 2>/dev/null )
	while IFS= read -r f; do
		case "$f" in
		*.gen.o|*main_gen_plugin.o)
			if has_marker "$f" '\(__tsan_\|__asan_\)'; then
				fail "$name: $f is instrumented (compile_rule objects must not be)"; extra=$((extra+1))
			fi;;
		esac
	done < <( { find "$B/src" -name '*.gen.o'; echo "$B/src/main_gen_plugin.o"; } 2>/dev/null )
	if [ "$re" != none ] && has_marker "$B/compile_rule" "$re"; then
		fail "$name: compile_rule is $re-instrumented (it must stay uninstrumented)"
	fi
	echo "  $name: $n files checked${missing:+, $missing not instrumented}${extra:+, $extra wrongly instrumented}"
	[ "$missing" -eq 0 ] && [ "$extra" -eq 0 ] && [ "$n" -gt 0 ]
}

# probe that the toolchain can compile and link a binary with the given
# sanitizer flag: a leg needs nothing more - it builds uninstrumented tools
# (compile_rule, gen_dpi_header) and only inspects objects with nm, never
# runs an instrumented binary
probe_san(){ # flag probe-name
	printf 'int main(void){return 0;}\n' > "$TMP/probe.$2.c"
	gcc "$1" "$TMP/probe.$2.c" -o "$TMP/probe.$2" > "$TMP/probe.$2.log" 2>&1
}

# a second `make` of the same flavor must be the no-op of a0f63108: nothing
# compiles and .build-flavor keeps its content and mtime. The only action
# lines allowed are the --refresh-plugin-engine recompile and the relinks
# it races (at most 7, measured at a0f63108; under -j that target runs
# parallel to the downstream relinks, so the no-op emits 3-7 lines; the
# sanitizer legs cap at 6 because compile_rule is linked from the separate
# *.gen.o objects that the refresh never touches). A stamp rewritten on
# every parse (a signature that never matches) shows up here as a full
# rebuild and a newer stamp.
noop_leg(){ # leg-name max-action-lines make-args...
	local name=$1 max=$2; shift 2
	local stamp="$B/.build-flavor" before after n objn ok=0
	before=$(stat -c %y "$stamp" 2>/dev/null; sha256sum "$stamp" 2>/dev/null)
	( cd "$B" && make -j"$JOBS" "$@" lib _prepare sec_server rule_info ) > "$TMP/make.$name.noop.log" 2>&1 || {
		cat "$TMP/make.$name.noop.log"; fail "$name: second same-flavor make failed"; return 1; }
	after=$(stat -c %y "$stamp" 2>/dev/null; sha256sum "$stamp" 2>/dev/null)
	[ "$before" = "$after" ] || { ok=1; \
		fail "$name: second same-flavor make rewrote .build-flavor"; }
	objn=$(grep -cE '^\[COMPILE\] (.*\.o|rules/)' "$TMP/make.$name.noop.log")
	[ "$objn" -eq 0 ] || { ok=1; \
		fail "$name: second same-flavor make recompiled $objn objects or rules"; }
	n=$(grep -cE '^\[(COMPILE|ARCHIVE|LIBRARY|RE-COMPILE)\]' "$TMP/make.$name.noop.log")
	[ "$n" -le "$max" ] || { ok=1; \
		fail "$name: second same-flavor make ran $n build actions, expected at most the a0f63108 no-op set ($max)"; }
	return $ok
}

build plain
check_tree none plain || true
noop_leg plain 7 || true

if probe_san -fsanitize=thread tsan; then
	build tsan TSAN=1
	check_tree '__tsan_' tsan || true
	noop_leg tsan 6 TSAN=1 || true
else
	echo "  => SKIPPED: no working TSan toolchain:"
	head -3 "$TMP/probe.tsan.log"
fi

if probe_san -fsanitize=address asan; then
	build asan ASAN=1
	check_tree '__asan_' asan || true
	noop_leg asan 6 ASAN=1 || true
else
	echo "  => SKIPPED: no working ASan toolchain:"
	head -3 "$TMP/probe.asan.log"
fi

if [ "$status" -eq 0 ]; then
	echo "  => OK: every flavor switch rebuilt all of its objects"
fi
exit $status
