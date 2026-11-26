#!/usr/bin/env bash
# message_t alignment (issues #64 and #66), run by `make check` as target
# check-message-align. message_t is declared __aligned (a cache line) but
# mmt_mem_alloc used to return data 16 bytes past the malloc base. The
# allocator and the message code are rebuilt here with
# -fsanitize=address,undefined and run by check/message_align.c, which
# creates, duplicates, retains and frees message_t blocks and asserts
# ptr % _Alignof(message_t) == 0 on each: on the unfixed allocator the
# first misaligned access inside create_message_t is a UBSan report and
# halt_on_error makes it fatal.
#
# Usage: check/check-message-align.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
status=0
fail(){ echo "  => FAILED: $*"; status=1; }

echo
echo "Testing message_t alignment under ASan+UBSan (issue #64)"

# the objects of a TSan build cannot link with ASan+UBSan (same platform
# limitation check-tsan.sh skips on); the alignment of the blocks a TSan
# build returns comes from the same code, so skipping loses nothing
if nm src/lib/*.o 2>/dev/null | grep -q ' __tsan_'; then
	echo "  => SKIPPED: cannot link a TSan build with ASan+UBSan"
	exit 0
fi

DPI="${MMT_BASE:-/opt/mmt}/dpi"
# same recipe as the Makefile's test.% rule, plus -fsanitize=address,
# undefined on the units under test: like check-fsm-bounds.sh the checked
# objects are linked, except mmt_alloc.o and message_t.o which are rebuilt
# sanitized so a misaligned access inside them is a UBSan report.
CF="-O2 -fPIC -Wall -DLEVEL1_DCACHE_LINESIZE=64 -I/usr/include/libxml2 -I$DPI/include -Isrc/lib -fsanitize=address,undefined"
if ! gcc $CF -c -o "$TMP/mmt_alloc.o" src/lib/mmt_alloc.c 2> "$TMP/build.log" \
|| ! gcc $CF -c -o "$TMP/message_t.o" src/lib/message_t.c 2>> "$TMP/build.log" \
|| ! gcc $CF -o "$TMP/message_align" check/message_align.c \
	"$TMP/mmt_alloc.o" "$TMP/message_t.o" \
	$(ls src/lib/*.o | grep -v '\.gen\.o$' | grep -v -e '/mmt_alloc\.o$' -e '/message_t\.o$') \
	-Wl,--export-dynamic -L"$DPI/lib" -L/usr/local/lib \
	-ldl -lpthread -lxml2 -lpcap -l:libmmt_tcpip.so -l:libmmt_core.so >> "$TMP/build.log" 2>&1; then
	cat "$TMP/build.log"
	fail "cannot build check/message_align.c (needs: make _prepare)"
	exit $status
fi

# a scratch run dir: mmt_sec_init loads ./rules and ./mmt-security.conf
mkdir -p "$TMP/run/rules"
cp rules/1.ssh.so rules/6.SYNFUL.so "$TMP/run/rules/"
cp mmt-security.conf "$TMP/run/"

( cd "$TMP/run" && UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
	ASAN_OPTIONS="detect_leaks=0" "$TMP/message_align" ) > "$TMP/run.log" 2>&1
rc=$?
cat "$TMP/run.log"
if [ $rc -ne 0 ]; then
	fail "check/message_align exited $rc (see the log above)"
fi

[ $status -eq 0 ] && echo "  => OK"
exit $status
