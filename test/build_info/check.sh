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
#      lists it and mmt_sec_standalone gives the same alerts as the new .so.
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
# shellcheck disable=SC2086
/usr/bin/gcc $cflags "$T/old.c" -o "$T/old.so" || fail "compile the .so without build info"
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

hdr = open("src/dpi/mmt_dpi.h").read()
m = re.search(r'mmt_version\(\)\{\s*return "([^"]*)";', hdr)
check(m and get("dpi.ids_from") == m.group(1), "dpi.ids_from is the mmt_version() of src/dpi/mmt_dpi.h")
check(get("dpi.ids_from_commit") and get("dpi.ids_from_commit") in (get("dpi.ids_from") or ""), "dpi.ids_from_commit")
# with mmt-dpi installed (as in make check), the installed library is probed
check(isinstance(get("dpi.installed"), str) and get("dpi.installed"), "dpi.installed (mmt-dpi is installed)")
check(get("dpi.ids_match_installed") is True, "dpi.ids_match_installed is true")
check(get("dpi.plugins") == ["libmmt_tcpip.so"], "dpi.plugins == [libmmt_tcpip.so]")

run = lambda *a: subprocess.run(a, capture_output=True, text=True).stdout.strip()
check(get("build.compiler") == "gcc " + run("gcc", "-dumpfullversion")
      or (get("build.compiler") or "").startswith("gcc " + run("gcc", "-dumpversion")), "build.compiler is gcc's version")
check(get("build.target") == run("/usr/bin/gcc", "-dumpmachine"), "build.target is gcc -dumpmachine")
check(" -fPIC -shared " in " " + (get("build.cflags") or "") + " ", "build.cflags has -fPIC -shared")
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
