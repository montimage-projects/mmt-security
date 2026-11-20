#!/usr/bin/env python3
"""compare.py - compare the rule (proto, att) ids measured by run.sh (issue #5, A0).

Usage: compare.py OUT_DIR...   (one directory per mmt-dpi version, in order)

Each OUT_DIR holds what in-container.sh wrote: dpi.txt, baked-committed-header.tsv,
baked-regenerated.tsv, core.tsv and compile-errors-*.txt. The report is Markdown:
the versions, every id per version, the differences, the affected rules, and a
build-on-X / load-on-Y matrix. Exit status: 0 when the report was produced.
"""
import os
import re
import sys
from collections import OrderedDict, defaultdict

COMMITTED = "committed-header"


def read_kv(path):
    kv = {}
    with open(path) as f:
        for line in f:
            k, _, v = line.rstrip("\n").partition("\t")
            kv[k] = v
    return kv


def read_baked(path):
    """rows: (file, rule_id, proto, att, proto_id, att_id, dpi_type)"""
    rows = []
    with open(path) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) == 7:
                rows.append(tuple(p))
    return rows


def read_core(path):
    ids = {}
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            proto, att, pid, aid, t = line.rstrip("\n").split("\t")
            ids[(proto, att)] = (pid, aid, t)
    return ids


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.rstrip("\n") for l in f if l.strip()]


PROTO_RE = re.compile(r'\{\.id = (\d+), \.name = "([^"]*)"')
ATT_RE = re.compile(r'\.id = +(\d+), \.data_type = (\w+) *, \.name = "([^"]*)"')


def read_registry(path):
    """(proto, att) -> (proto_id, att_id, data type name) for a whole mmt_dpi.h"""
    reg = {}
    proto = None
    pid = None
    if not os.path.exists(path):
        return reg
    with open(path) as f:
        for line in f:
            m = PROTO_RE.search(line)
            if m:
                pid, proto = m.group(1), m.group(2)
                reg[(proto, "")] = (pid, "", "")
            for m in ATT_RE.finditer(line):
                reg[(proto, m.group(3))] = (pid, m.group(1), m.group(2))
    return reg


def registry_section(p, regs):
    """whole DPI registry: how many ids differ between consecutive versions"""
    p("## Whole DPI registry (every protocol and attribute, not only the rules')\n")
    p("| from -> to | protocols | attributes | removed | added | id changed | type changed |")
    p("|---|---|---|---|---|---|---|")
    labels = list(regs)
    for a, b in zip(labels, labels[1:]):
        ra, rb = regs[a], regs[b]
        removed = [k for k in ra if k not in rb]
        added = [k for k in rb if k not in ra]
        both = [k for k in ra if k in rb]
        moved = [k for k in both if ra[k][:2] != rb[k][:2]]
        typed = [k for k in both if ra[k][2] != rb[k][2]]
        nprot = sum(1 for k in rb if k[1] == "")
        p("| %s -> %s | %d | %d | %d | %d | %d | %d |" % (
            a, b, nprot, len(rb) - nprot, len(removed), len(added), len(moved), len(typed)))
        for name, lst in (("id changed", moved), ("type changed", typed)):
            if lst:
                p("|  | %s: %s%s ||||||" % (name, ", ".join(
                    "%s.%s %s->%s" % (k[0], k[1] or "*", "/".join(ra[k][:2]) if name == "id changed" else ra[k][2],
                                      "/".join(rb[k][:2]) if name == "id changed" else rb[k][2])
                    for k in lst[:12]), " ..." if len(lst) > 12 else ""))
        if removed:
            p("|  | removed: %s%s ||||||" % (", ".join("%s.%s" % (k[0], k[1] or "*") for k in removed[:12]),
                                              " ..." if len(removed) > 12 else ""))
    p("")


def main(dirs):
    versions = OrderedDict()
    for d in dirs:
        label = os.path.basename(os.path.normpath(d))
        v = {
            "info": read_kv(os.path.join(d, "dpi.txt")),
            "committed": read_baked(os.path.join(d, "baked-committed-header.tsv")),
            "regen": read_baked(os.path.join(d, "baked-regenerated.tsv")),
            "core": read_core(os.path.join(d, "core.tsv")),
            "err_committed": read_lines(os.path.join(d, "compile-errors-committed-header.txt")),
            "err_regen": read_lines(os.path.join(d, "compile-errors-regenerated.txt")),
        }
        versions[label] = v

    out = []
    p = out.append

    # ---- versions ----------------------------------------------------------
    p("## Versions measured\n")
    p("| label | commit | commit date | mmt_version() | build image |")
    p("|---|---|---|---|---|")
    for label, v in versions.items():
        i = v["info"]
        p("| %s | `%s` | %s | %s | %s, gcc %s |" % (
            label, i.get("commit", "?")[:12], i.get("commit_date", "?")[:10],
            i.get("mmt_version", "?"), i.get("image", "?"), i.get("gcc", "?")))
    p("")

    # ---- the committed header gives the same result in every container ----
    first = next(iter(versions.values()))
    same = all(v["committed"] == first["committed"] for v in versions.values())
    p("## compile_rule with the committed `src/dpi/mmt_dpi.h`\n")
    p("The rules encoded with the committed header are %s in every container "
      "(the installed mmt-dpi %s change the baked ids)." % (
          "byte-identical" if same else "NOT identical",
          "does not" if same else "DOES"))
    p("")

    # sources: the committed header, then each version's regenerated header
    sources = OrderedDict()
    sources[COMMITTED] = first["committed"]
    for label, v in versions.items():
        sources[label] = v["regen"]

    # rules and pairs
    rules = OrderedDict()          # (file, rule_id) -> set of pairs
    pair_rules = defaultdict(set)  # pair -> {(file, rule_id)}
    ids = defaultdict(dict)        # pair -> source -> (pid, aid, t)
    for src, rows in sources.items():
        for f, rid, proto, att, pid, aid, t in rows:
            pair = (proto, att)
            rules.setdefault((f, rid), set()).add(pair)
            pair_rules[pair].add((f, rid))
            ids[pair][src] = (pid, aid, t)
    files = sorted({f for f, _ in rules})
    p("## Coverage\n")
    p("- %d rule files, %d rules (properties), %d distinct (proto, att) pairs." % (
        len(files), len(rules), len(ids)))
    for label, v in versions.items():
        for kind in ("err_committed", "err_regen"):
            groups = defaultdict(list)
            for e in v[kind]:
                f, _, msg = e.partition(": ")
                groups[msg].append(f.split(".")[0])
            for msg, fs in groups.items():
                p("- compile_rule cannot encode %d rule file(s) with the %s header of %s (%s): `%s`" % (
                    len(fs), "committed" if kind == "err_committed" else "regenerated",
                    label, ", ".join(fs), msg))
    p("")

    # ---- regenerated header == libmmt_core at run time --------------------
    p("## Regenerated header vs. libmmt_core at run time\n")
    for label, v in versions.items():
        bad = []
        for pair, per in ids.items():
            core = v["core"].get(pair)
            hdr = per.get(label)
            if hdr is None:
                if core and core[0] != "-" and core[1] != "-":
                    bad.append("%s.%s: missing from header, core %s/%s" % (pair + core[:2]))
                continue
            if core is None or (hdr[0], hdr[1]) != (core[0], core[1]) or hdr[2] != core[2]:
                bad.append("%s.%s: header %s/%s/%s, core %s" % (pair + hdr + (core,)))
        p("- %s: %s" % (label, "all %d pairs agree" % len(ids) if not bad
                        else "%d disagree: %s" % (len(bad), "; ".join(bad))))
    p("")

    # ---- per-pair table of differing ids ----------------------------------
    srcs = list(sources)

    def fmt(t):
        return "%s/%s" % (t[0], t[1]) if t else "missing"

    diff_pairs = [pair for pair in sorted(ids)
                  if len({ids[pair].get(s, ("missing",))[:2] for s in srcs}) > 1]
    type_pairs = [pair for pair in sorted(ids)
                  if len({ids[pair][s][2] for s in srcs if s in ids[pair]}) > 1]
    p("## (proto, att) pairs whose ids differ\n")
    p("%d of %d pairs differ (an id changes or the pair is missing) across the sources; "
      "%d change dpi_type." % (len(diff_pairs), len(ids), len(type_pairs)))
    p("")
    if diff_pairs:
        p("| proto.att | " + " | ".join(srcs) + " | rules |")
        p("|---" * (len(srcs) + 2) + "|")
        for pair in diff_pairs:
            p("| %s.%s | %s | %s |" % (
                pair[0], pair[1],
                " | ".join(fmt(ids[pair].get(s)) for s in srcs),
                len(pair_rules[pair])))
        p("")
    if type_pairs:
        p("dpi_type changes: " + ", ".join(
            "%s.%s (%s)" % (pr[0], pr[1], " / ".join(
                "%s=%s" % (s, ids[pr][s][2]) for s in srcs if s in ids[pr]))
            for pr in type_pairs))
        p("")

    # ---- build on X, load on Y ---------------------------------------------
    p("## Build on X, load on Y: rules whose baked ids are wrong\n")
    p("Rows: the header the `.so` was compiled with. Columns: the libmmt_core it is "
      "loaded into. Cell: rules (of %d) with at least one wrong or missing id; "
      "0 means every rule is safe." % len(rules))
    p("")
    targets = list(versions)
    p("| built with \\ loaded into | " + " | ".join(targets) + " |")
    p("|---" * (len(targets) + 1) + "|")
    affected = {}
    for s in srcs:
        cells = []
        for t in targets:
            bad = set()
            for pair, rs in pair_rules.items():
                if s not in ids[pair]:
                    continue  # the rule does not compile with s
                core = versions[t]["core"].get(pair)
                if core is None or ids[pair][s][:2] != core[:2]:
                    bad |= {r for r in rs if pair in rules[r]}
            # rules that did not compile against s are not counted
            affected[(s, t)] = bad
            cells.append(str(len(bad)))
        p("| %s | %s |" % (s, " | ".join(cells)))
    p("")

    # ---- affected rules in detail ------------------------------------------
    p("## Affected rules\n")
    shown = set()
    for (s, t), bad in affected.items():
        if not bad or s == t:
            continue
        key = (s, t)
        if key in shown:
            continue
        shown.add(key)
        names = defaultdict(list)
        for f, rid in sorted(bad, key=lambda r: (int(r[1]) if r[1].isdigit() else 0, r[0])):
            names[f].append(rid)
        p("- built with **%s**, loaded into **%s** (%d rules): %s" % (
            s, t, len(bad), ", ".join("%s (%s)" % (f, ",".join(r)) for f, r in sorted(names.items()))))
    if not shown:
        p("None.")
    p("")

    regs = OrderedDict()
    regs[COMMITTED] = read_registry(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "..", "..", "src", "dpi", "mmt_dpi.h"))
    for label in versions:
        regs[label] = read_registry(os.path.join(dirs[list(versions).index(label)], "mmt_dpi.h"))
    registry_section(p, regs)

    # ---- full id table -------------------------------------------------------
    p("## All pairs\n")
    p("<details><summary>%d pairs, proto_id/att_id/dpi_type per source, and the rule ids using each</summary>\n" % len(ids))
    p("| proto.att | " + " | ".join(srcs) + " | rules |")
    p("|---" * (len(srcs) + 2) + "|")
    for pair in sorted(ids):
        rids = sorted({int(r[1]) for r in pair_rules[pair]})
        p("| %s.%s | %s | %s |" % (
            pair[0], pair[1],
            " | ".join("/".join(ids[pair][s]) if s in ids[pair] else "missing" for s in srcs),
            ",".join(map(str, rids)) if len(rids) <= 12 else "%d rules" % len(rids)))
    p("\n</details>")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
