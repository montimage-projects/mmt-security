#!/bin/bash
# test/build_info/check.sh - build info of rule .so files (fork issue #6).
#
# Run by `make check-build-info` (part of `make check`) from the repository
# root, after compile_rule, rule_info and mmt_sec_standalone are built.
#   1. builds one rule, checks every field of its build info, and that the
#      DPI id hash matches the ids in the generated C;
#   2. checks the .note.mmt.build note holds the same JSON (readelf/objcopy);
#   3. builds the same rule without the build-info block (what a compile_rule
#      without build info generates), and proves it still loads: rule_info
#      lists it and mmt_sec_standalone gives the same alerts as the new .so;
#   4. compile_rule's extra gcc option comes after the source, so its -l
#      libraries are linked; too long an option is an error;
#   5. the build info of every rules/*.so: dpi.plugins names the plugins that
#      register the protocols the rules use;
#   6. robustness: invalid UTF-8, a date gmtime cannot give, no builder, a
#      non-ELF file, crafted ELF notes and section tables, version strings.
# Needs python3 and binutils. Usage: test/build_info/check.sh VERSION GIT_VERSION
set -euo pipefail

VERSION=${1:?version}
GIT_VERSION=${2:-}
RULE=rules/13.datainSYN.xml
RULE_ID=13
PCAP=check/pcap/13.data_in_SYN.pcap
REPO=$(pwd)

for t in python3 readelf objcopy objdump nm gcc; do
	command -v $t >/dev/null || { echo "  => FAILED: $t is needed by $0"; exit 1; }
done

T=$(mktemp -d "${TMPDIR:-/tmp}/mmt-sec-build-info.XXXXXX")
trap 'rm -rf "$T"' EXIT

fail(){ echo "  => FAILED: $*"; exit 1; }

# ---- 1. a .so with build info ------------------------------------------------
MMT_SEC_BUILDER=check-build-info ./compile_rule "$T/new.so" "$RULE" > "$T/compile.log" 2>&1 \
	|| { cat "$T/compile.log"; fail "compile_rule $RULE"; }
./compile_rule "$T/gen.c" "$RULE" -c > /dev/null 2>&1 || fail "compile_rule -c $RULE"

nm -D --defined-only "$T/new.so" | grep -qw mmt_sec_get_rule_build_info \
	|| fail "new.so does not export mmt_sec_get_rule_build_info"
./rule_info --build-info --json "$T/new.so" > "$T/info.json"
./rule_info --build-info "$T/new.so" > "$T/info.txt"
./rule_info --abi > "$T/abi.txt"

# ---- 2. the ELF note -----------------------------------------------------------
readelf -n "$T/new.so" > "$T/notes.txt"
grep -q "Displaying notes found in: .note.mmt.build" "$T/notes.txt" || fail "readelf -n shows no .note.mmt.build"
grep -A2 "notes found in: .note.mmt.build" "$T/notes.txt" | grep -qE "^ +MMT +0x" || fail "the note owner is not MMT"
objcopy -O binary --only-section=.note.mmt.build "$T/new.so" "$T/note.bin"
objdump -T "$T/new.so" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -uV | tail -1 > "$T/glibc.txt" || true

# ---- 3. a .so without build info ---------------------------------------------
sed '/BEGIN mmt-security rule build info/,/END mmt-security rule build info/d' "$T/gen.c" > "$T/old.c"
grep -q "mmt_sec_get_rule_build_info" "$T/old.c" && fail "could not strip the build info from the generated C"
cflags=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["build"]["cflags"])' "$T/info.json")
# build.cflags are the gcc arguments in their order, the files written {source} and {output}
cmd=${cflags//\{source\}/$T/old.c}
cmd=${cmd//\{output\}/$T/old.so}
[ "$cmd" != "$cflags" ] || fail "build.cflags has no {source} / {output}: $cflags"
# shellcheck disable=SC2086
/usr/bin/gcc $cmd || fail "compile the .so without build info with build.cflags"
nm -D --defined-only "$T/old.so" | grep -qw mmt_sec_get_rule_build_info && fail "old.so exports the build info"
readelf -S "$T/old.so" | grep -q "note.mmt.build" && fail "old.so has the note"
[ "$(./rule_info --build-info --json "$T/old.so")" = "null" ] || fail "rule_info --build-info --json old.so is not null"

for v in new old; do
	./rule_info "$T/$v.so" > "$T/$v.rule_info.txt" 2>&1 || fail "rule_info $v.so"
	grep -q "Rule id: $RULE_ID" "$T/$v.rule_info.txt" || fail "rule_info $v.so does not list rule $RULE_ID"
	# the engine loads ./rules/*.so
	mkdir -p "$T/$v/rules" "$T/$v/out"
	cp "$T/$v.so" "$T/$v/rules/"
	( cd "$T/$v" && "$REPO/mmt_sec_standalone" -t "$REPO/$PCAP" -f "$T/$v/out/" ) > "$T/$v.run.log" 2>&1 \
		|| { cat "$T/$v.run.log"; fail "mmt_sec_standalone with $v.so"; }
	cat "$T/$v"/out/*.csv 2>/dev/null | cut -d, -f5- > "$T/$v.alerts.csv"
	grep -q "^$RULE_ID," "$T/$v.alerts.csv" || fail "no alert of rule $RULE_ID with $v.so"
done
diff "$T/new.alerts.csv" "$T/old.alerts.csv" > /dev/null || fail "new.so and old.so give different alerts"

# ---- the fields --------------------------------------------------------------
python3 -I - "$T" "$RULE" "$RULE_ID" "$VERSION" "$GIT_VERSION" <<'EOF'
import hashlib, json, re, struct, subprocess, sys
T, xml, rule_id, version, git = sys.argv[1:6]
info = json.load(open(T + "/info.json"))
errors = []

def check(cond, what):
    if not cond:
        errors.append(what)

def get(path):
    v = info
    for k in path.split("."):
        if not isinstance(v, dict) or k not in v:
            errors.append("missing field " + path)
            return None
        v = v[k]
    return v

# every documented field is present
for f in ("schema", "rule_ids", "xml.file", "xml.sha256", "rule_abi.hash", "rule_abi.plugin_version",
          "mmt_security.version", "mmt_security.git", "mmt_security.index",
          "dpi.ids_from", "dpi.ids_from_commit", "dpi.installed", "dpi.installed_commit",
          "dpi.ids_match_installed", "dpi.ids_hash", "dpi.ids", "dpi.plugins",
          "build.compiler", "build.target", "build.cflags", "build.glibc_min", "build.os",
          "build.builder", "build.date"):
    get(f)

check(get("schema") == 1, "schema is 1")
check(get("rule_ids") == [int(rule_id)], "rule_ids == [%s]" % rule_id)
check(get("xml.file") == xml.split("/")[-1], "xml.file")
check(get("xml.sha256") == hashlib.sha256(open(xml, "rb").read()).hexdigest(), "xml.sha256 is the sha256 of the XML")

abi = open(T + "/abi.txt").read().split("\n")
check(get("rule_abi.hash") == abi[0], "rule_abi.hash equals `rule_info --abi` of this engine")
check(abi[0] == "sha256:" + hashlib.sha256(abi[1].encode()).hexdigest(), "rule ABI hash is the sha256 of the layout")
check(re.fullmatch(r"\d+\.\d+\.\d+", get("rule_abi.plugin_version") or ""), "rule_abi.plugin_version")

check(get("mmt_security.version") == version, "mmt_security.version == " + version)
if git:
    check(get("mmt_security.git") == git, "mmt_security.git == " + git)

# dpi.ids: the (proto, att) entries of the generated C, and their hash
c = open(T + "/gen.c").read()
baked = set()
for m in re.finditer(r'\{\.proto = "([^"]*)", \.proto_id = (\d+), \.att = "([^"]*)", \.att_id = (\d+), '
                     r'\.data_type = -?\d+, \.dpi_type = (-?\d+)\}', c):
    baked.add((m.group(1), int(m.group(2)), m.group(3), int(m.group(4)), int(m.group(5))))
ids = [tuple(x) for x in get("dpi.ids") or []]
check(len(baked) > 0, "found proto_atts in the generated C")
check(set(ids) == baked, "dpi.ids == the ids in the generated C (%s vs %s)" % (sorted(ids), sorted(baked)))
canon = "".join("%s,%d,%s,%d,%d\n" % x for x in sorted(baked, key=lambda x: (x[0].encode(), x[2].encode())))
check(get("dpi.ids_hash") == "sha256:" + hashlib.sha256(canon.encode()).hexdigest(),
      "dpi.ids_hash is the sha256 of the canonical ids of the generated C")

# dpi.ids_from is the label compiled into compile_rule with the id table, not
# the src/dpi/mmt_dpi.h on disk: make can regenerate that file without
# rebuilding compile_rule (doc/rule-abi-stability.md)
cr = open("compile_rule", "rb").read()
labels = set(re.findall(rb"\d+\.\d+\.\d+ \([0-9a-f]{7,40}\)", cr))
check((get("dpi.ids_from") or "").encode() in labels,
      "dpi.ids_from %r is the mmt_version() compiled into compile_rule %r" % (get("dpi.ids_from"), labels))
check(get("dpi.ids_from_commit") and get("dpi.ids_from_commit") in (get("dpi.ids_from") or ""), "dpi.ids_from_commit")
# with mmt-dpi installed (as in make check), the installed library is probed
check(isinstance(get("dpi.installed"), str) and get("dpi.installed"), "dpi.installed (mmt-dpi is installed)")
check(get("dpi.ids_match_installed") is True, "dpi.ids_match_installed is true")
check(get("dpi.plugins") == ["libmmt_tcpip.so"], "dpi.plugins == [libmmt_tcpip.so]")

run = lambda *a: subprocess.run(a, capture_output=True, text=True).stdout.strip()
check(get("build.compiler") == "gcc " + run("gcc", "-dumpfullversion")
      or (get("build.compiler") or "").startswith("gcc " + run("gcc", "-dumpversion")), "build.compiler is gcc's version")
check(get("build.target") == run("/usr/bin/gcc", "-dumpmachine"), "build.target is gcc -dumpmachine")
check("#define MMT_SEC_RULE_TARGET" in c and '\\"target\\":\\"" MMT_SEC_RULE_TARGET "\\"' in c,
      "build.target comes from the predefined macros of the compiler of the .so")
# the order compile_gen_code uses: the include dirs and the extra option after the source
check(re.fullmatch(r"(-O\d|-g -O0 -DDEBUG_MODE) -fPIC -shared \{source\} -o \{output\} -I \./src/lib -I \./src/dpi "
                   r"-I/opt/mmt/security/include -I/opt/mmt/dpi/include", get("build.cflags") or ""),
      "build.cflags is <opt> -fPIC -shared {source} -o {output} -I <includes>: %r" % get("build.cflags"))
check(get("build.glibc_min") == open(T + "/glibc.txt").read().strip(), "build.glibc_min is the highest GLIBC_ of objdump -T")
osr = dict(l.split("=", 1) for l in open("/etc/os-release").read().splitlines() if "=" in l)
check(get("build.os") == osr.get("PRETTY_NAME", "").strip('"'), "build.os is PRETTY_NAME")
check(get("build.builder") == "check-build-info", "build.builder follows MMT_SEC_BUILDER")
check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", get("build.date") or ""), "build.date")

# the note holds the same JSON
note = open(T + "/note.bin", "rb").read()
namesz, descsz, ntype = struct.unpack("=III", note[:12])
name = note[12:12 + namesz]
desc = note[12 + ((namesz + 3) & ~3):][:descsz].rstrip(b"\0").decode()
check(name == b"MMT\0" and ntype == 0x4d4d5401, "note owner MMT, type 0x4d4d5401")
check(json.loads(desc) == info and desc == open(T + "/info.json").read().strip(), "the note holds the JSON of the function")

# the indented output is the same document
txt = open(T + "/info.txt").read()
check(json.loads(txt) == info, "rule_info --build-info (indented) is the same JSON")

if errors:
    for e in errors:
        print("  => FAILED: " + e)
    sys.exit(1)
print("  => build info: %d fields, %d ids, hash %s" % (sum(len(v) if isinstance(v, dict) else 1 for v in info.values()),
                                                     len(ids), info["dpi"]["ids_hash"][:19]))
EOF
echo "  => OK: build info of $RULE, its note, and a .so without build info still loads"

# ---- 4. compile_rule's extra gcc option --------------------------------------
# a rule calling a function of libfoo.so, built with '-L<dir> -lfoo': gcc links
# --as-needed, so -lfoo must come after the source to be linked
mkdir -p "$T/foo"
echo 'int foo_check( void ){ return 42; }' > "$T/foo/foo.c"
gcc -fPIC -shared "$T/foo/foo.c" -o "$T/foo/libfoo.so" || fail "build libfoo.so"
cat > "$T/foo.xml" <<'XML'
<beginning>
<embedded_functions><![CDATA[
int foo_check( void );
static int em_foo( const void *data ){ return data != NULL && foo_check() == 42; }
]]></embedded_functions>
<property value="THEN" delay_units="s" delay_min="0" delay_max="0" property_id="990" type_property="ATTACK"
    description="calls libfoo">
      <event value="COMPUTE" event_id="1" description="foo" boolean_expression="(#em_foo(ip.src) == 1)"/>
      <event value="COMPUTE" event_id="2" description="IP addresses" boolean_expression="(ip.src != ip.dst)"/>
</property>
</beginning>
XML
./compile_rule "$T/foo.so" "$T/foo.xml" "-L$T/foo -lfoo" > "$T/foo.log" 2>&1 || { cat "$T/foo.log"; fail "compile_rule foo.xml -lfoo"; }
readelf -d "$T/foo.so" | grep -q 'NEEDED.*\[libfoo\.so\]' || fail "foo.so built with -lfoo does not need libfoo.so"
LD_LIBRARY_PATH="$T/foo" ./rule_info "$T/foo.so" > "$T/foo.rule_info.txt" 2>&1 || fail "rule_info foo.so"
grep -q "^Found 1 rule" "$T/foo.rule_info.txt" || { cat "$T/foo.rule_info.txt"; fail "rule_info cannot load foo.so"; }
foo_cflags=$(./rule_info --build-info --json "$T/foo.so" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["build"]["cflags"])')
case "$foo_cflags" in
	*"-fPIC -shared {source} -o {output} -I ./src/lib "*" -L$T/foo -lfoo") ;;
	*) fail "build.cflags of foo.so is not in the order gcc got it: $foo_cflags" ;;
esac
echo "  => OK: -lfoo comes after the source: foo.so needs libfoo.so and loads"

# too long an extra option is an error, not a silently truncated command
long=$(python3 -I -c 'print("-DX" + "x" * 15300)')
if ./compile_rule "$T/long.so" "$RULE" "$long" > "$T/long.log" 2>&1; then fail "compile_rule accepted a 15 KB gcc option"; fi
grep -q "too long" "$T/long.log" || { cat "$T/long.log"; fail "no clear error for a 15 KB gcc option"; }
[ ! -e "$T/long.so" ] || fail "compile_rule built a .so with a truncated option"
echo "  => OK: a 15 KB gcc option is rejected"

# ---- 5. dpi.plugins of every rule ----------------------------------------------
for so in rules/*.so; do
	./rule_info --build-info --json "$so" > "$T/all.$(basename "$so").json" || fail "rule_info --build-info $so"
done
python3 -I - "$T" <<'PY'
import glob, json, sys
T = sys.argv[1]
# the protocols libmmt_core registers itself (mmt-dpi src/mmt_core/src/proto_meta.c)
core = {"meta", "unknown"}
# rules that read only generic attributes (ip.src, icmp.type, ...): their
# protocols are registered by libmmt_tcpip all the same
tcpip = {20, 26, 27, 32, 39, 41, 46, 54, 62, 68, 69, 70, 71, 72, 73, 76, 92}
errors, n, seen = [], 0, set()
for f in sorted(glob.glob(T + "/all.*.json")):
    info = json.loads(open(f, "rb").read().decode("utf-8"))
    n += 1
    so = f.split("/all.")[-1][:-5]
    d = info["dpi"]
    protos = {x[0] for x in d["ids"]} - core
    if protos and d["ids_match_installed"] and not d["plugins"]:
        errors.append("%s uses %s but dpi.plugins is %r" % (so, sorted(protos), d["plugins"]))
    for r in info["rule_ids"]:
        if r in tcpip:
            seen.add(r)
            if "libmmt_tcpip.so" not in (d["plugins"] or []):
                errors.append("rule %d (%s): dpi.plugins %r lacks libmmt_tcpip.so" % (r, so, d["plugins"]))
if tcpip - seen:
    errors.append("rules not found in rules/*.so: %s" % sorted(tcpip - seen))
for e in errors:
    print("  => FAILED: " + e)
if errors:
    sys.exit(1)
print("  => OK: dpi.plugins of the %d rules/*.so name the plugins of their protocols" % n)
PY

# ---- 6. robustness -------------------------------------------------------------
# a Latin-1 file name: the JSON stays UTF-8, the invalid byte becomes U+FFFD
latin1="$T/caf$(printf '\351').xml"
cp "$RULE" "$latin1"
./compile_rule "$T/latin1.so" "$latin1" > /dev/null 2>&1 || fail "compile_rule on a Latin-1 file name"
./rule_info --build-info --json "$T/latin1.so" > "$T/latin1.json"
python3 -I -c 'import json,sys; i = json.loads(open(sys.argv[1], "rb").read().decode("utf-8")); sys.exit(i["xml"]["file"] != "caf�.xml")' "$T/latin1.json" \
	|| fail "the JSON of a Latin-1 file name is not UTF-8 with U+FFFD: $(cat "$T/latin1.json")"

# a date gmtime_r cannot give is null; the epoch is the epoch
for e in 99999999999999999 0; do
	SOURCE_DATE_EPOCH=$e ./compile_rule "$T/date.so" "$RULE" > /dev/null 2>&1 || fail "compile_rule with SOURCE_DATE_EPOCH=$e"
	./rule_info --build-info --json "$T/date.so" > "$T/date.$e.json"
done
python3 -I -c 'import json,sys; sys.exit(json.load(open(sys.argv[1]))["build"]["date"] is not None)' "$T/date.99999999999999999.json" \
	|| fail "build.date of SOURCE_DATE_EPOCH=99999999999999999 is not null: $(cat "$T/date.99999999999999999.json")"
python3 -I -c 'import json,sys; sys.exit(json.load(open(sys.argv[1]))["build"]["date"] != "1970-01-01T00:00:00Z")' "$T/date.0.json" \
	|| fail "build.date of SOURCE_DATE_EPOCH=0"

# no MMT_SEC_BUILDER: the builder is unknown (the host name is not recorded)
env -u MMT_SEC_BUILDER ./compile_rule "$T/nob.so" "$RULE" > /dev/null 2>&1 || fail "compile_rule without MMT_SEC_BUILDER"
./rule_info --build-info --json "$T/nob.so" > "$T/nob.json"
python3 -I -c 'import json,sys; sys.exit(json.load(open(sys.argv[1]))["build"]["builder"] is not None)' "$T/nob.json" \
	|| fail "build.builder is not null without MMT_SEC_BUILDER: $(cat "$T/nob.json")"

# rule_info --build-info on files that are not valid ELF shared objects
expect_error(){ # expect_error MESSAGE FILE
	if ./rule_info --build-info "$2" > "$T/err.out" 2> "$T/err.txt"; then fail "rule_info --build-info $2 succeeded: $(cat "$T/err.out")"; fi
	grep -q "$1" "$T/err.txt" || fail "rule_info --build-info $2: no '$1' error: $(cat "$T/err.txt" "$T/err.out")"
	if ./rule_info --build-info --json "$2" > "$T/err.out" 2>&1; then fail "rule_info --build-info --json $2 succeeded"; fi
}
expect_error "not an ELF shared object" readme.md
: > "$T/empty.so"
expect_error "not an ELF shared object" "$T/empty.so"
python3 -I - "$T/new.so" "$T" <<'PY'
import struct, sys
src, T = sys.argv[1:3]
data = bytes(open(src, "rb").read())
assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, "a 64-bit little-endian ELF"
shoff, = struct.unpack_from("<Q", data, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
sh = lambda i: shoff + i * shentsize
stroff, = struct.unpack_from("<Q", data, sh(shstrndx) + 0x18)
note = [i for i in range(shnum)
        if data[stroff + struct.unpack_from("<I", data, sh(i))[0]:].split(b"\0")[0] == b".note.mmt.build"][0]
# 1. a build-info note whose n_descsz is 0xFFFFFFFF, without NUL (its 32-bit
#    padding wraps to 0): .note.mmt.build points to it
d = bytearray(data)
off = (len(d) + 3) & ~3
d += b"\0" * (off - len(d))
d += struct.pack("<III", 4, 0xFFFFFFFF, 0x4d4d5401) + b"MMT\0" + b"{" * 64
struct.pack_into("<QQ", d, sh(note) + 0x18, off, 12 + 4 + 64)
open(T + "/crafted-descsz.so", "wb").write(d)
# 2. the section headers moved to an odd offset
d = bytearray(data)
odd = len(d) | 1
d += b"\0" * (odd - len(d)) + data[shoff:shoff + shnum * shentsize]
struct.pack_into("<Q", d, 0x28, odd)
open(T + "/crafted-shoff.so", "wb").write(d)
PY
expect_error "invalid note" "$T/crafted-descsz.so"
expect_error "invalid note" "$T/crafted-shoff.so"
echo "  => OK: Latin-1 name, out-of-range date, no builder, non-ELF and crafted .so files"

# mmt_sec_get_version_number_from_string reads no byte after the version (ASan)
cat > "$T/version_test.c" <<'C'
#include <stdio.h>
#include <stdint.h>
#include "version.h"
int main( void ){
	printf( "%u %u\n", mmt_sec_get_version_index(), mmt_sec_get_required_plugin_version_number() );
	return 0;
}
C
if gcc -fsanitize=address -fno-omit-frame-pointer -DVERSION_NUMBER="\"$VERSION\"" -I src/lib \
		src/lib/version.c "$T/version_test.c" -o "$T/version_test" 2> /dev/null; then
	ASAN_OPTIONS=detect_leaks=0 "$T/version_test" > "$T/version.txt" 2>&1 || { cat "$T/version.txt"; fail "version string parsing (ASan)"; }
	echo "  => OK: version index $(cut -d' ' -f1 "$T/version.txt"), no over-read under ASan"
else
	echo "  => SKIPPED: version string parsing under ASan (gcc has no -fsanitize=address)"
fi
echo "  => OK: compile_rule options, dpi.plugins of all rules, robustness"
