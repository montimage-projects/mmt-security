# Rule `.so` stability across mmt-dpi versions (A0)

This report measures whether a compiled rule (`rules/*.so`) built against one
mmt-dpi can be loaded safely into another. It also says whether the rule ABI
changed between mmt-security tags. It is the A0 experiment of Track A (fork
issue #5). The build-info, bundle and loader-check work builds on it.

Measured on 2026-11-20 at `6a95b61` (fork `main` `c658615` plus this report),
in `ubuntu:24.04` containers (aarch64, gcc 13.3.0). The
measurements can be reproduced with:

```sh
tools/dpi-id-stability/run.sh           # DPI ids: 5 mmt-dpi builds, ~3-10 min, docker, no sudo
tools/dpi-id-stability/abi-layout.sh    # rule ABI struct layouts at every v1.2.* tag
tools/dpi-id-stability/header-regen.sh  # when make regenerates src/dpi/mmt_dpi.h, which ids get baked
rm -rf tools/dpi-id-stability/.work     # afterwards: the scratch directory (gitignored), ~300 MB
```

`run.sh` measures the `HEAD` commit (`git archive HEAD`), not the working tree:
`make all` can rewrite the tracked `src/dpi/mmt_dpi.h`, and a regenerated header
must not be measured as the committed one. It warns when `rules/` or `src/`
differ from `HEAD`. The mmt-dpi refs are pinned to full commits (a moved tag is
reported), and the image by digest. The apt build packages are not pinned;
`dpi.txt` records each build's commit, image and gcc.

## Verdict

- **No protocol or attribute id changed** between the mmt-dpi versions measured
  (fd93012d, 6b1c9f53, v1.8.0, v1.10.2, v1.10.3). This holds for the 98
  (proto, att) pairs used by the 96 rules of the 95 `rules/*.xml` files, and for the whole DPI registry
  (679 protocols and 7530 attributes in v1.10.3). The same goes for the
  attribute data types (`dpi_type`) the rules use, and for the `data_types`
  enum.
- So a rule `.so` built against any of 6b1c9f53, v1.8.0, v1.10.2, v1.10.3 or the
  committed header reads the right attributes on any of them: **0 of 96 rules
  are affected**.
- Pairs do go missing. The 30 DICOM rules (200-229) use `dicom.*`, which
  fd93012d does not have. Loaded into such a DPI, those rules register unknown
  ids (`register_extraction_attribute` fails silently,
  `src/main_sec_standalone.c:216-228`) and never fire. Nothing logs it.
- Between releases the registry grows (fd93012d to 6b1c9f53: +1 protocol and
  +31 attributes, DICOM; 6b1c9f53 to 1.8.0: +2 protocols and +20 attributes;
  1.8.0 to 1.10.2: +7 protocols and +85 attributes), loses one attribute
  (`http.header` is gone in 1.10.x), and changes 3 attribute types
  (`quic_ietf.{dst_conn_id,src_conn_id,token}`, in 1.10.x). No rule uses these today, but nothing protects a future rule
  from them.
- Stability holds by convention only. Nothing in mmt-dpi or mmt-security enforces
  it, and the loader checks only the mmt-security version index
  (`src/lib/plugins_engine.c:94-104`).

## How the ids get into a rule `.so`

1. `compile_rule` resolves each `proto.att` of a rule to numbers when it parses
   the rule (`src/lib/expression.c:94-98`: `get_protocol_id_by_name`,
   `get_attribute_id_by_protocol_id_and_attribute_name`,
   `get_attribute_data_type`).
2. Those functions are **not** the ones in `libmmt_core`. They are `static inline`
   lookups over a table in `src/dpi/mmt_dpi.h` (`src/main_gen_dpi.c:162-216`), a
   header generated from one mmt-dpi build by `gen_dpi_header` and **committed to
   the repository**. `compile_rule`, `rule_info` and `libmmt_security2.so` do not
   even link `libmmt_core` (see "Resolvers" below).
3. `gen_code.c` writes the numbers into the generated C
   (`src/lib/gen_code.c:535`, `.proto_id = ..., .att_id = ..., .dpi_type = ...`).
   They are compiled into the `.so`.
4. At run time the engine registers those numbers with the running `libmmt_core`
   (`src/main_sec_standalone.c:216-262`). Nothing resolves the names again.

So the ids a rule bakes are those of the table **compiled into the
`compile_rule` binary** (into `expression.o`), and its DPI label is the
`mmt_version()` compiled into `gen_code.o`. Neither the header file on disk nor
the installed mmt-dpi says reliably which table that is.

### When `make` regenerates the header, and what it rebuilds

The Makefile has two rules that matter:

- `gen_dpi $(MMT_DPI_HEADER): $(MMT_DPI_DIR)`: the header is regenerated when it
  is missing, or older than the `/opt/mmt/dpi` **directory**. Only `all` (and
  the `test.%` targets) depend on the header. `compile_rule`, `rule_info`,
  `sample_rules` and `check` do not.
- `%.o: %.c`: the objects depend on their `.c` file only, not on the headers
  they include.

Two consequences, both reproduced by `tools/dpi-id-stability/header-regen.sh`
(transcript below):

- **(a) Only a first install regenerates the header.** A directory's mtime
  changes only when one of its direct entries is created or removed. Installing
  mmt-dpi for the first time creates `/opt/mmt/dpi`, so a checkout made before
  it (a fresh container, CI, the mmt-stack image) gets a regenerated header
  from `make all`. Upgrading or downgrading mmt-dpi rewrites files in
  `/opt/mmt/dpi/lib` and `/opt/mmt/dpi/include`, not the entries of
  `/opt/mmt/dpi`, so `make all` keeps the old header. On a host that upgrades
  mmt-dpi, the header never follows.
- **(b) A regenerated header does not rebuild the objects.** When `make all`
  regenerates the header after `compile_rule` was built,
  `expression.o`, `gen_code.o` and `compile_rule` stay as they are. The header
  file (and `git status`) then says the installed DPI, while `compile_rule`
  keeps baking the old table and the old label. This lasts until `make clean`.

Transcript, in `ubuntu:24.04` (aarch64) with the mmt-dpi v1.10.2 and v1.10.3
release `.deb`s (checked against each release's SHA256SUMS), on
`git archive HEAD` at `6a95b61` extracted with `tar -m` (files get the
extraction time, as with a `git clone`). The probe is rule 15 with
`http.user_agent` replaced by `http.header`, an attribute that the committed
table has and 1.10.x does not. "Data type for http.header has not implemented
yet" means the name **resolved** to an id and mmt-security cannot encode its
type; "Attribute http.header has not implemented yet" means it did not resolve.

```
== (a) first install after the checkout, then a downgrade and an upgrade
$ tar -C /b -xmf /w/sec.tar
$ dpkg -i /w/debs/mmt-dpi_1.10.3.deb >/dev/null; dpkg-query -W mmt-dpi
  mmt-dpi	1.10.3-6a0afb46
$ stat -c '%y %n' /opt/mmt/dpi /b/src/dpi/mmt_dpi.h
  2026-11-20 16:26:12.802590914 +0000 /opt/mmt/dpi
  2026-11-20 16:26:12.553589560 +0000 /b/src/dpi/mmt_dpi.h
  make -n all regenerates the header: yes
$ tar -C /a -xmf /w/sec.tar    # a checkout made while 1.10.3 is installed
  make -n all regenerates the header: no
$ stat -c '%y %n' /opt/mmt/dpi /opt/mmt/dpi/lib
  2026-11-20 16:26:12.802590914 +0000 /opt/mmt/dpi
  2026-11-20 16:26:12.818591001 +0000 /opt/mmt/dpi/lib
$ dpkg -i /w/debs/mmt-dpi_1.10.2.deb >/dev/null; dpkg-query -W mmt-dpi    # downgrade
  dpkg: warning: downgrading mmt-dpi from 1.10.3-6a0afb46 to 1.10.2-a84a6050
  mmt-dpi	1.10.2-a84a6050
$ stat -c '%y %n' /opt/mmt/dpi /opt/mmt/dpi/lib
  2026-11-20 16:26:12.802590914 +0000 /opt/mmt/dpi
  2026-11-20 16:26:13.270593458 +0000 /opt/mmt/dpi/lib
  make -n all regenerates the header: no
$ dpkg -i /w/debs/mmt-dpi_1.10.3.deb >/dev/null; dpkg-query -W mmt-dpi    # upgrade
  mmt-dpi	1.10.3-6a0afb46
$ stat -c '%y %n' /opt/mmt/dpi /opt/mmt/dpi/lib
  2026-11-20 16:26:12.802590914 +0000 /opt/mmt/dpi
  2026-11-20 16:26:13.584595165 +0000 /opt/mmt/dpi/lib
  make -n all regenerates the header: no

== (b) the header is regenerated, the objects are not rebuilt
$ make -j1 compile_rule rule_info >/dev/null 2>&1; head -c 110 src/dpi/mmt_dpi.h; echo
  /* This code is generated automatically on 2026-01-29 23:08:49 using MMT-DPI v1.7.10 (fd93012d). */
$ probe; baked; label
  probe http.header: HALT_SEC: Error 2: Data type for http.header has not implemented yet
  dpi version 1.7.10 (fd93012d)
  gen_code.o holds: 1.7.10 (fd93012d)
$ make -j1 all 2>&1 | grep -E 'Generate|COMPILE'    # nothing in src/lib is recompiled
  >>> Generate list of protocols and their attributes to /b/src/dpi/mmt_dpi.h
  [COMPILE] main_sec_server.o
  [COMPILE] sec_server
  [RE-COMPILE] plugins_engine.o
  [COMPILE] main_sec_standalone.o
  [COMPILE] standalone
$ head -c 110 src/dpi/mmt_dpi.h; echo; cmp -s src/dpi/mmt_dpi.h /orig/src/dpi/mmt_dpi.h && echo 'same as committed' || echo 'differs from committed (git status: modified)'
  /* This code is generated automatically on 2026-11-20 16:26:15 using MMT-DPI v1.10.3 (6a0afb46). */
  differs from committed (git status: modified)
$ probe; baked; label    # still the committed table and label
  probe http.header: HALT_SEC: Error 2: Data type for http.header has not implemented yet
  dpi version 1.7.10 (fd93012d)
  gen_code.o holds: 1.7.10 (fd93012d)
$ make clean >/dev/null; make -j1 all >/dev/null 2>&1; head -c 110 src/dpi/mmt_dpi.h; echo
  /* This code is generated automatically on 2026-11-20 16:26:15 using MMT-DPI v1.10.3 (6a0afb46). */
$ probe; baked; label    # after make clean
  probe http.header: HALT_SEC: Error 2: Attribute http.header has not implemented yet
  dpi version 1.10.3 (6a0afb46)
  gen_code.o holds: 1.10.3 (6a0afb46)

== (c) which binaries link libmmt_core
  compile_rule           NEEDED: libxml2.so.2 libc.so.6 ld-linux-aarch64.so.1
  rule_info              NEEDED: libxml2.so.2 libc.so.6 ld-linux-aarch64.so.1
  libmmt_security2.so    NEEDED: libc.so.6 ld-linux-aarch64.so.1
  mmt_sec_standalone     NEEDED: libxml2.so.2 libpcap.so.0.8 libmmt_core.so.1 libc.so.6 ld-linux-aarch64.so.1
```

(`baked` compiles `rules/11.ip_size.xml` to a `.so` and prints its
`rule_info` DPI version; `label` greps the version string out of
`src/lib/gen_code.o`.)

In short, the baked table depends on the build history of the tree, not on a
target or a file you can inspect:

- the committed table, whatever mmt-dpi is installed: `make compile_rule
  sample_rules` (or `make check`) on any tree; `make all` on a tree checked out
  after mmt-dpi was installed, upgraded or downgraded; and `make all` on a tree
  whose `compile_rule` was built before the header was regenerated;
- the installed DPI's table: a tree whose objects were all built after the
  header was regenerated (a fresh checkout followed by a first install and
  `make all`, as in a fresh container, upstream CI's `make clean-all && make`
  or the mmt-stack image; or `make clean` after a regeneration).

### The committed header and its label

The committed header starts with `using MMT-DPI v1.7.10 (fd93012d)`, but its table
is identical to that of 6b1c9f53 (all 8096 entries; it has DICOM, which fd93012d
lacks). It was probably generated from a fd93012d tree with the DICOM branch
merged in.

Because `gen_code.c` includes that header, `mmt_version()` in
`src/lib/gen_code.c:582` is the header's too, as compiled into `gen_code.o`. A rule
built with the committed table reports `dpi version 1.7.10 (fd93012d)` in
`rule_info`, even when DPI 1.10.3 is installed (transcript above). Today's `.dpi`
field therefore says, at best, which header `gen_code.o` was compiled with. It
does not say what was installed, and the label can itself be wrong: the
committed one says fd93012d for a 6b1c9f53 table. If only some objects are
rebuilt after a regeneration (for example after an edit of `gen_code.c`), the
label and the table come from different headers.

### Resolvers

`compile_rule`, `rule_info` and `libmmt_security2.so` do not link `libmmt_core`
(`readelf -d` above); only `mmt_sec_standalone` does. Every `src/lib` TU that
includes `../dpi/mmt_dpi.h` without `mmt_core.h` before it (`expression.c`,
`gen_code.c`, `mmt_security.c`, `mmt_single_security.c`) gets its own
`static inline` copies of `get_protocol_id_by_name`,
`get_attribute_id_by_protocol_id_and_attribute_name`, `get_attribute_data_type`
and the others, over the header table. They are guarded by `#ifndef MMT_CORE_H`,
so only a TU that includes `mmt_core.h` first (as `dpi_message_t.h` does) calls
the real ones.

A check written in those files with those function names therefore compares
the baked ids against the header table, not against the running DPI, and
always reports OK. See the loader-check recommendations below.

## Method

`tools/dpi-id-stability/run.sh` does this for each mmt-dpi ref, in a fresh
`ubuntu:24.04` container:

1. It builds mmt-dpi from source at that commit, from a clone of
   https://github.com/Montimage/mmt-dpi, and installs it in the container.
2. It builds `compile_rule` twice: with the committed `src/dpi/mmt_dpi.h`, and
   with a header regenerated from this DPI (`make gen_dpi` on a tree with no
   objects yet, so `compile_rule` really compiles the regenerated table).
3. It encodes every `rules/*.xml` with `compile_rule -c` and reads every
   `{.proto, .proto_id, .att, .att_id, .dpi_type}` entry of the generated
   `proto_atts_<id>` arrays. These are the ids a `.so` built that way contains.
4. It resolves the same pairs at run time with `resolve_ids.c`, a small program
   linked to that `libmmt_core` after `init_extraction()` (all plugins loaded).

`compare.py` then compares the sources. The full output is in the appendix.

| ref | commit | date | `mmt_version()` | why |
|---|---|---|---|---|
| fd93012d | `fd93012d5f92` | 2026-01-06 | 1.7.10 (fd93012d) | named in the committed header |
| 6b1c9f53 | `6b1c9f5380a4` | 2026-04-13 | 1.7.10 (6b1c9f53) | old upstream CI pin (`.github/workflows/c-cpp.yml`) |
| v1.8.0 | `af4c3cd7c4d0` | 2026-07-23 | 1.8.0 (af4c3cd7) | the only 1.8.x tag |
| v1.10.2 | `a84a6050963c` | 2026-11-10 | 1.10.2 (a84a6050) | |
| v1.10.3 | `6a0afb468cdb` | 2026-11-15 | 1.10.3 (6a0afb46) | current release, mmt-stack pin |

Checks that hold in every container:

- the rules encoded with the committed header are byte-identical whatever DPI
  is installed;
- for every pair, the regenerated header and the run-time `libmmt_core`
  give the same ids and the same type. The header is a faithful snapshot.

## Results

### Build on X, load on Y

Each cell counts the rules (of 96) that have at least one missing pair, or a
pair whose `proto_id`, `att_id` or `dpi_type` differs, when a `.so` built with
the row's header is loaded into the column's `libmmt_core`.

| built with \ loaded into | fd93012d | 6b1c9f53 | v1.8.0 | v1.10.2 | v1.10.3 |
|---|---|---|---|---|---|
| committed header | 30 | 0 | 0 | 0 | 0 |
| fd93012d | 0 | 0 | 0 | 0 | 0 |
| 6b1c9f53 | 30 | 0 | 0 | 0 | 0 |
| v1.8.0 | 30 | 0 | 0 | 0 | 0 |
| v1.10.2 | 30 | 0 | 0 | 0 | 0 |
| v1.10.3 | 30 | 0 | 0 | 0 | 0 |

The 30 rules are the DICOM rules 200-229 (16 `dicom.*` pairs, proto id 701). With
the fd93012d header, `compile_rule` refuses them
(`Error 2: Protocol dicom has not implemented yet`). With the 66 rules it can
build, a fd93012d `.so` is safe on every later version.

### Whole DPI registry

Protocols and attributes are counted separately (the counts are those of the
`to` side; the attributes of a removed or added protocol count as removed or
added attributes).

| from -> to | protocols | attributes | protocols added | protocols removed | attributes added | attributes removed | id changed | type changed |
|---|---|---|---|---|---|---|---|---|
| committed header -> fd93012d | 669 | 7395 | 0 | 1 (DICOM) | 0 | 31 (DICOM) | 0 | 0 |
| fd93012d -> 6b1c9f53 | 670 | 7426 | 1 (DICOM) | 0 | 31 (DICOM) | 0 | 0 | 0 |
| 6b1c9f53 -> v1.8.0 | 672 | 7446 | 2 | 0 | 20 | 0 | 0 | 0 |
| v1.8.0 -> v1.10.2 | 679 | 7530 | 7 | 0 | 85 | 1 (`http.header`) | 0 | 3 (`quic_ietf.*`) |
| v1.10.2 -> v1.10.3 | 679 | 7530 | 0 | 0 | 0 | 0 | 0 | 0 |

The `data_types` enum (`types_defs.h`, 35 values) is identical in all five, and
matches the copy in `src/main_gen_dpi.c`.

### Id assumptions outside the rules

These are not baked into rule `.so` files, but they assume ids:

- `src/lib/message_t.c:158` used to hardcode `proto_id == 354` (TCP) and
  `6 <= att_id <= 14` (`flags`, `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`,
  `cwr`) to drop zero-valued TCP flags. Both numbers hold in all five versions
  measured. The Montimage#28 fix (fork PR #11, now in `main`) removed that
  filter, so no hardcoded id is left there.
- `src/main_sec_standalone.c:245-256` and `src/lib/dpi_message_t.h:112-200` use
  `PROTO_TCP`, `PROTO_IP`, `TCP_PAYLOAD_LEN`, `IP_OPTS` and so on. They come from
  the installed mmt-dpi headers when the engine is built, so they always match
  the DPI the engine is linked against.
- `src/main_gen_dpi.c:26-60` keeps its own copy of the `data_types` names, by
  index. It matches all five versions.

## Rule ABI across mmt-security tags

A rule `.so` shares these with the engine: `rule_info_t`, `proto_attribute_t` and
`rule_version_info_t` (`src/lib/plugin_header.h`). Through the inline helpers it
also shares `message_t` and `message_element_t` (`src/lib/message_t.h`, read by
`get_element_data_message_t`), `mmt_array_t`, the FSM structs of
`src/lib/mmt_fsm.h`, and the header of the `mmt_mem_alloc` buffers
(`mmt_memory_t`, read by `mmt_mem_size` and `mmt_mem_cmp`). Since 1.2.22 it no
longer shares `rule_engine_t` (below). `tools/dpi-id-stability/abi-layout.sh`
compiles a `sizeof`/`offsetof` probe against `src/lib` of every v1.2.* tag:

| tags | rule_info_t, proto_attribute_t, rule_version_info_t | message_t | REQUIRE_PLUGIN |
|---|---|---|---|
| v1.2.0 - v1.2.5 | unchanged | 64 bytes, `elements@16`, `hash` u64 | 1.2.0 |
| v1.2.6 - v1.2.12 | unchanged | 128 bytes, `flow_id` and `user_data` added, `elements@24` | 1.2.7 |
| v1.2.13 - v1.2.20 | unchanged | `hash` becomes `mmt_bit_t` (32 bytes, at 34) | 1.2.7 |
| 1.2.21 (unreleased, fork #51) | `rule_info_t` 104 bytes: `instance_keys@96` appended; `rule_engine_t` changed too (below) | unchanged | 1.2.21 |
| 1.2.22 (unreleased, fork #56) | unchanged; the guards no longer read `rule_engine_t`, they call `mmt_sec_rule_engine_get_msg_values` (below) | unchanged | 1.2.22 |

- `rule_info_t` (96 bytes on LP64), `proto_attribute_t` (32) and
  `rule_version_info_t` (40) did not change from v1.2.0 to v1.2.20.
  `mmt_fsm.h` and `mmt_array_t.h` did not change after v1.2.6.
- The v1.2.6 `message_t` change moved `elements`, which rule code reads. It came
  with the `REQUIRE_PLUGIN` bump to 1.2.7, so the loader refuses older `.so`
  files. That is the one check that works today.
- The v1.2.13 change (`hash`, `ba8e58a`) came without a bump. Rule code does not
  read `message_t.hash` (it reads `elements` and `elements_count`, whose offsets
  did not move), so v1.2.6+ `.so` files stay compatible. A struct hash would
  still have flagged it. Only the bump discipline protects the ABI today.

### `rule_engine_t` was part of the plugin ABI (1.2.21)

The layout probe above covers the structs of `plugin_header.h`,
`message_t.h`, `mmt_array_t.h` and `mmt_fsm.h`. Up to 1.2.21 it missed one:
the guards that `compile_rule` generates `#include "rule_verif_engine.h"`
(`src/lib/gen_code.c`, the includes of the generated code) and read the
per-message attribute values as `_engine->msg_values`, where `_engine` is
the `rule_engine_t` of the fsm (`fsm_get_user_data`). The offset of
`msg_values` is therefore compiled into every 1.2.21 rule `.so`. So
`rule_engine_t`, an engine-private struct, was in effect part of the plugin
ABI from the addition of `msg_values` (fork #51, PR #53) to 1.2.21. 1.2.22
removes it (next section).

The fork #51 instance index (PR #55) changed both structs:

| struct | before (97441d79, stamped 1.2.20) | after (1.2.21) |
|---|---|---|
| `rule_info_t` | 96 bytes, `version@88` last | 104 bytes, `instance_keys@96` appended |
| `rule_engine_t` | 112 bytes, `msg_values@96` | 136 bytes, `msg_values@120` (`event_index`, `next_reg_seq` and `timeout_heap` inserted before it) |

(LP64, aarch64 and x86_64.) Both directions crash without a gate: an engine
of the new layout reads `instance_keys` past the end of an old rule's
`rule_info_t` (SIGSEGV in `rule_engine_init`), and an engine of the old
layout running a new rule makes its guard read the wrong `rule_engine_t`
slot (SIGSEGV inside the generated guard).

`VERSION` 1.2.20 was stamped by `compile_rule` both before and after the
change, so `REQUIRE_PLUGIN` could not stay at 1.2.20: rules of the old
layout would pass a `>= 1.2.20` check. The fix:

- `VERSION` and `REQUIRE_PLUGIN` are 1.2.21, a stamp that no `compile_rule`
  of the old layout wrote;
- the loader (`_filter_rules_by_version`, `src/lib/plugins_engine.c`) also
  refuses a rule stamped **newer** than the engine, with the warning
  "Ignored rule N as it was built for a newer engine". A rule is loaded
  only if `REQUIRE_PLUGIN <= stamp <= engine version`;
- the loader reads only the `rule_info_t` prefix (`id`, `description`,
  `version`) before the check, and the first rule of a plugin decides for
  the whole plugin: the rules array of another layout has another stride,
  so its second element cannot be located;
- `check/check-plugin-abi.sh` (`make check`) loads rules built by the
  `compile_rule` of 97441d79 and rules stamped one patch version above the
  engine, and expects both refused, with a warning and exit 0.

Two limits remained in 1.2.21:

- **Engines already deployed cannot be protected.** An engine of
  `REQUIRE_PLUGIN` 1.2.7 (v1.2.7 to v1.2.20, and the fork before this
  change) has no upper bound: it accepts a 1.2.21 rule, whose guards then
  read its `rule_engine_t` at the wrong offset. Nothing in a 1.2.21 rule
  `.so` can make an old engine refuse it. The #55 re-review saw such a run
  produce plausible alerts instead of crashing: the failure can be silent.
  1.2.22 rules fail loudly on these engines instead (next section).
- **The upper bound is strict.** A 1.2.21 engine also refuses a rule built
  by a later `compile_rule` whose layout did not change.

**Rule: rebuild the rules with the engine.** Install a rule `.so` only with
the mmt-security it was compiled by (same `VERSION`), and recompile every
third-party rule when mmt-security is upgraded. `rule_info --build-info`
prints the stamp of a rule `.so` (`mmt_security.version`). This still holds
in 1.2.22: the bounds of the loader did not change.

### `rule_engine_t` leaves the plugin ABI (1.2.22)

Fork #56 removes `rule_engine_t` from what a rule `.so` shares with the
engine:

- the generated guards read the message values through a function the
  engine exports, `mmt_sec_rule_engine_get_msg_values( const rule_engine_t * )`
  (`src/lib/rule_verif_engine.h`), with the engine of `fsm_get_user_data( fsm )`:

  ```c
  const void * const *_mv = mmt_sec_rule_engine_get_msg_values( (const rule_engine_t *) fsm_get_user_data( fsm ));
  if( unlikely( _mv == NULL )) return 0;
  ```

  It is a real exported function, defined in `rule_verif_engine.c` and never
  `static inline`: an inline accessor would compile the offset of
  `msg_values` back into every rule;
- `rule_verif_engine.h`, the engine header that the generated code includes,
  declares `rule_engine_t` as an incomplete type
  (`typedef struct rule_engine_struct rule_engine_t;`). The struct is defined
  in `rule_verif_engine_internal.h`, which only the engine's own files
  (`rule_verif_engine.c`, `mmt_single_security.c`) include (`make install`
  installs it with the other headers of `src/lib`, but no header that the
  generated code includes reaches it). A guard that read a field of
  `rule_engine_t`, or its `sizeof`, would no longer compile;
- no other field of `rule_engine_t` is read by generated code. The generated
  C of every rule of `rules/`, `rules/properties_all/` and `check/timeout/`
  (223 files; the two OCPP rules of `properties_all` do not compile for an
  unrelated reason, their protocol is not in mmt-dpi) contains no `_engine->`
  and no other use of `rule_engine_t` than the cast above. 222 of their 223
  `.so` list `mmt_sec_rule_engine_get_msg_values` as an undefined symbol; the
  other one, `properties_all/26.ip_scan`, has no guard that reads the current
  message, so it does not call the accessor.

`rule_engine_t` can therefore change without a `REQUIRE_PLUGIN` bump, as
long as the accessor keeps its meaning (element i of the returned array is
the data of `rule_info_t.proto_atts[i]` in the message being verified, or
NULL; the array is NULL when the rule has no `proto_atts`).

`VERSION` and `REQUIRE_PLUGIN` are 1.2.22: a 1.2.21 rule still reads
`rule_engine_t.msg_values` at offset 120, so the engine must refuse it
before the struct changes again. Both directions are now clean:

| rule | engine | result |
|---|---|---|
| 1.2.21 (3904b83c, guards read `msg_values@120`) | 1.2.22 | refused: "Ignored rule N as it is not up to date (built by version 1.2.21, this engine needs 1.2.22 or later)", exit 0 |
| 1.2.22 | 1.2.21 or older, including the engines of `REQUIRE_PLUGIN` 1.2.7 that have no upper bound | `dlopen` fails before the version check: "Cannot open library: rules/6.SYNFUL.so. rules/6.SYNFUL.so: undefined symbol: mmt_sec_rule_engine_get_msg_values", and the engine halts (exit 1). Loud, not a wrong-memory read; `rule_info` halts the same way |
| rule without a version stamp (`rule_info_t.version` NULL, a hand-made `.so`) | 1.2.22 | refused: "Ignored rule N as it has no version stamp (not built by compile_rule)" |

The second row was measured with the engine and `rule_info` of 3904b83c.
Their loader `dlopen`s with `RTLD_NOW`, as every engine since v1.2.0 does
(`plugins_engine.c`), and the symbol exists in no engine before 1.2.22, so
an older engine halts the same way. That closes the first limit of 1.2.21
for most rules built from now on: an old engine cannot run them silently.
Only for a `.so` that imports the accessor, though: a rule none of whose
guards reads the current message (only constants or history `.N` values;
`properties_all/26.ip_scan` is one) imports nothing new, so an engine of
`REQUIRE_PLUGIN` 1.2.7 still loads it, with the risks of the first limit
(its 104-byte `rule_info_t` array is indexed with a 96-byte stride). And an
old engine halts rather than skipping the rule. So the "rebuild the rules
with the engine" rule stays.
`check/check-plugin-abi.sh` (`make check`) builds the rules of the first row
with the `compile_rule` of 3904b83c (`MMT_SEC_ABI_BASE_1221`), and checks the
third row and that the headers of the generated code (the include lines
`gen_code.c` writes) keep the struct opaque.

**Cost.** The accessor is a call, through the PLT, per guard evaluation that
reads the current message, where 1.2.21 read a field. On
`perf51.pcap` (100k packets, every rule of `rules/`, 0 alerts on both),
taskset-pinned, median of 5, the 1.2.22 engine is 1.5 to 3.1 % slower
than 3904b83c, depending on the core (the numbers and the options are in the
fork PR that closes fork issue #56).

`rule_abi.hash` (`mmt_sec_get_rule_abi_layout`, `src/lib/rule_build_info.c`)
and the layout probe (`tools/dpi-id-stability/abi_layout.c`) now cover this
whole surface: besides the structs of the table above, the instance-key
tables (`fsm_instance_key_t`, `fsm_instance_key_component_t`), the fsm
structs the generated code initialises (`fsm_delay_t`, `fsm_transition_t`,
`fsm_state_t`), the `fsm_t` fields that its inline helpers read
(`execution_trace`, `user_data`; not the size of `fsm_t`, which a rule never
allocates), `mmt_memory_t`, the enum values the generated code compiles in
(`FSM_EVENT_TYPE_TIMEOUT`, `FSM_ACTION_*`, `MMT_SEC_MSG_DATA_TYPE_*`,
`RULE_TYPE_*`), and a `rule_engine_t:opaque{mmt_sec_rule_engine_get_msg_values}`
entry for the accessor. `rule_info --abi` of 1.2.22 on aarch64:

```
sha256:4710cdd268f8c58c76f31723507d8e4768994557a1bc2a2f3bf6f7f920a332f0
proto_attribute_t:32{proto@0:8,att@8:8,proto_id@16:4,att_id@20:4,data_type@24:4,dpi_type@28:4}
rule_version_info_t:40{created_date@0:8,hash@8:8,number@16:8,index@24:4,dpi@32:8}
rule_info_t:104{id@0:4,type_id@4:4,type_string@8:8,description@16:8,if_satisfied@24:8,if_not_satisfied@32:8,proto_atts_count@40:1,events_count@41:1,proto_atts@48:8,proto_atts_events@56:8,excluded_filter@64:8,create_instance@72:8,hash_message@80:8,version@88:8,instance_keys@96:8}
message_element_t:24{proto_id@0:4,att_id@4:4,data_type@8:4,data@16:8}
message_t:128{counter@0:8,timestamp@8:8,flow_id@16:8,elements@24:8,elements_count@32:2,hash@34:32,user_data@88:8}
mmt_array_t:16{elements_count@0:8,data@8:8}
fsm_instance_key_component_t:12{msg_att_index@0:2,his_event_id@2:2,his_att_index@4:2,data_type@8:4}
fsm_instance_key_t:16{components_count@0:1,components@8:8}
fsm_delay_t:48{time_min@0:8,time_max@8:8,time_min_sign@16:4,time_max_sign@20:4,counter_min@24:8,counter_max@32:8,counter_min_sign@40:4,counter_max_sign@44:4}
fsm_transition_t:32{event_type@0:2,guard@8:8,action@16:4,target_state@24:8}
fsm_state_t:88{delay@0:48,is_temporary@48:1,description@56:8,transitions@64:8,transitions_count@72:8,entry_action@80:4,exit_action@84:4}
fsm_t{execution_trace@64:8,user_data@72:8}
mmt_memory_t:16{ref_count@0:4,size@4:4,data@8:8}
enums{FSM_EVENT_TYPE_TIMEOUT=0,FSM_ACTION_DO_NOTHING=0,FSM_ACTION_CREATE_INSTANCE=1,FSM_ACTION_RESET_TIMER=2,MMT_SEC_MSG_DATA_TYPE_NUMERIC=0,MMT_SEC_MSG_DATA_TYPE_STRING=1,MMT_SEC_MSG_DATA_TYPE_BINARY=2,RULE_TYPE_ATTACK=0,RULE_TYPE_SECURITY=1,RULE_TYPE_EVASION=2,RULE_TYPE_TEST=3}
rule_engine_t:opaque{mmt_sec_rule_engine_get_msg_values}
require_plugin:1.2.22
```

(One line per entry here; the real output has them on one line, separated by
`;`.) The functions a rule calls (`fsm_init`, `mmt_mem_alloc`, `mmt_sec_log`,
...) are part of the ABI too; their signatures are not hashed, and the
`dlopen` with `RTLD_NOW` refuses a rule that needs a function the engine
does not export.

## Recommendations

### For the build info (fork issue #6)

The build info must describe what `compile_rule` compiled in, not the
environment of the build. The header file on disk and the installed
`/opt/mmt/dpi` tell you nothing reliable about the baked ids (cases (a) and (b)
above). So `gen_code.c` should record, from the table compiled into
`compile_rule`:

- **the baked tuples**: the sorted `proto, proto_id, att, att_id, dpi_type`
  the `.so` uses, so the loader can re-resolve each one by name and name the
  pair that differs;
- **a hash of those tuples, not of the whole registry.** The registry changed
  at 4 of the 5 steps measured while no id moved. A whole-registry hash would
  flag every release even though every rule was safe. Include `dpi_type`:
  types did change in 1.10.x;
- **a hash of the compiled-in DPI table** (the whole table in `expression.o`,
  computed by `compile_rule` at run time), to tell two builds' tables apart;
- **its label**: `mmt_version()` as compiled into `gen_code.o`. It is
  informative only. It can be wrong (the committed header says fd93012d for a
  6b1c9f53 table), and it can come from another header than the table if only
  some objects were rebuilt;
- **the installed DPI version, as a separate, informative field.**
  `compile_rule` does not link `libmmt_core`, so it has to `dlopen` the
  installed `libmmt_core` (and call its `mmt_version()`) to read it. When it
  differs from the label, the build used a stale or committed table; that is
  worth a build-time warning, not an error.

Also store a rule ABI hash over the `sizeof`/`offsetof` layout of the shared
structs above, next to `REQUIRE_PLUGIN`. It would have caught v1.2.13.

### For the rule bundle (fork issue #7)

A bundle must carry rules built against a known table. Two mmt-security build
fixes would make that predictable (not changed in this PR, which is doc and
tooling only):

- make `src/dpi/mmt_dpi.h` a real prerequisite of the objects that include it
  (`expression.o`, `gen_code.o`, `mmt_security.o`, `mmt_single_security.o`),
  so a regenerated header rebuilds `compile_rule`, `rule_info` and the library
  (fixes case (b));
- regenerate the header from the installed DPI's contents (for example, a
  generated temporary header replacing the real one only when it differs, or a
  stamp keyed on the installed `mmt_version()` and table hash), not from the
  `/opt/mmt/dpi` directory mtime (fixes case (a)). Generating it outside the
  source tree would also stop `make all` from modifying a tracked file.

Until then, a bundle build should run `make clean-all && make` (it removes the
header and every object, so the header is regenerated from the installed DPI
and everything is compiled against it), then check the label in `rule_info`
against the installed DPI.

### Default policy for the loader check (fork issue #8)

| condition | result |
|---|---|
| rule ABI hash differs from the engine's | FAIL |
| any (proto, att) of the rule does not resolve in the running `libmmt_core` (removed attribute, missing plugin: the DICOM case) | FAIL |
| any pair resolves to a different `proto_id`/`att_id` than the baked one | FAIL |
| any pair has a different `dpi_type` (the `quic_ietf` case) | FAIL |
| all ids and types match (the hash of the re-resolved tuples equals the baked tuple hash), but the DPI label or commit differs | WARN once per load, not per rule (see below) |
| no build info (a `.so` built before #6) | WARN, then fall back to re-resolving `rule_info_t.proto_atts` by name |
| everything matches | OK |

**Resolve against the running DPI, not the header.** The engine library,
`rule_info` and `compile_rule` do not link `libmmt_core`, and every `src/lib`
TU that includes `../dpi/mmt_dpi.h` has `static inline` resolvers over the
header table (see "Resolvers" above). A check that re-resolves names with
those functions compares the baked ids against the header and always says OK.
#8 must therefore resolve:

- in the engine: from a TU that includes `mmt_core.h` and not
  `../dpi/mmt_dpi.h` (or through `dlsym` of the real symbols), after the
  probe's `init_extraction()`;
- in `rule_info --check`: by `dlopen` of the target `libmmt_core`, then
  `init_extraction()`, then the name-lookup functions through `dlsym`. The
  target is a `--dpi` path or the installed one; it is never the header.

The same applies to the "no build info" fallback: re-resolving
`rule_info_t.proto_atts` by name is only meaningful with the real resolvers.

**Keep WARN readable.** The committed header's label (`1.7.10 (fd93012d)`)
never matches an installed DPI, so "label differs, ids match" would fire for
every rule on almost every deployment. Log it once per load (one line naming
both labels and the number of rules, or at INFO), and key the per-rule result
on the tuple hash rather than the label: a rule whose re-resolved tuples hash
to its baked tuple hash is OK whatever the label says. The real WARNs and FAILs
are then not drowned out.

Since every id has been stable so far, FAIL should not fire on today's rules
and DPI versions. Warn-only can therefore be the default for the first release,
as #8 plans, and strict mode (`MMT_SEC_STRICT_RULE_COMPAT=1`) can be made the
default once the check has run without false FAILs. The id check needs no
build info: `rule_info_t.proto_atts` already carries the names and the baked ids.
Old `.so` files can be checked too.

### Other findings

- A missing id is silent today. Logging when `register_extraction_attribute`
  fails would make the DICOM case visible without the full check.
- The committed `src/dpi/mmt_dpi.h` says fd93012d but holds the 6b1c9f53 table.
  Whether a build bakes it depends on the build history of the tree (see
  above); the #7 recommendations would make it predictable.

## Appendix: full output of `tools/dpi-id-stability/run.sh`

### Versions measured

| label | commit | commit date | mmt_version() | build image |
|---|---|---|---|---|
| fd93012d | `fd93012d5f92` | 2026-01-06 | 1.7.10 (fd93012d) | Ubuntu 24.04.5 LTS aarch64, gcc 13.3.0 |
| 6b1c9f53 | `6b1c9f5380a4` | 2026-04-13 | 1.7.10 (6b1c9f53) | Ubuntu 24.04.5 LTS aarch64, gcc 13.3.0 |
| v1.8.0 | `af4c3cd7c4d0` | 2026-07-23 | 1.8.0 (af4c3cd7) | Ubuntu 24.04.5 LTS aarch64, gcc 13.3.0 |
| v1.10.2 | `a84a6050963c` | 2026-11-10 | 1.10.2 (a84a6050) | Ubuntu 24.04.5 LTS aarch64, gcc 13.3.0 |
| v1.10.3 | `6a0afb468cdb` | 2026-11-15 | 1.10.3 (6a0afb46) | Ubuntu 24.04.5 LTS aarch64, gcc 13.3.0 |

### compile_rule with the committed `src/dpi/mmt_dpi.h`

The rules encoded with the committed header are byte-identical in every container (the installed mmt-dpi does not change the baked ids).

### Coverage

- 95 rule files, 96 rules (properties), 98 distinct (proto, att) pairs.
- compile_rule cannot encode 30 rule file(s) with the regenerated header of fd93012d (200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229): `HALT_SEC: Error 2: Protocol dicom has not implemented yet.`

### Regenerated header vs. libmmt_core at run time

- fd93012d: all 98 pairs agree
- 6b1c9f53: all 98 pairs agree
- v1.8.0: all 98 pairs agree
- v1.10.2: all 98 pairs agree
- v1.10.3: all 98 pairs agree

### (proto, att) pairs whose ids differ

16 of 98 pairs differ (an id changes or the pair is missing) across the sources; 0 change dpi_type.

| proto.att | committed-header | fd93012d | 6b1c9f53 | v1.8.0 | v1.10.2 | v1.10.3 | rules |
|---|---|---|---|---|---|---|---|
| dicom.abstract_syntax | 701/19 | missing | 701/19 | 701/19 | 701/19 | 701/19 | 1 |
| dicom.affected_sop_class_uid | 701/17 | missing | 701/17 | 701/17 | 701/17 | 701/17 | 1 |
| dicom.application_context | 701/6 | missing | 701/6 | 701/6 | 701/6 | 701/6 | 1 |
| dicom.called_ae_title | 701/4 | missing | 701/4 | 701/4 | 701/4 | 701/4 | 3 |
| dicom.calling_ae_title | 701/5 | missing | 701/5 | 701/5 | 701/5 | 701/5 | 1 |
| dicom.command_field | 701/14 | missing | 701/14 | 701/14 | 701/14 | 701/14 | 3 |
| dicom.data_set_type | 701/21 | missing | 701/21 | 701/21 | 701/21 | 701/21 | 1 |
| dicom.message_id | 701/18 | missing | 701/18 | 701/18 | 701/18 | 701/18 | 2 |
| dicom.patient_name | 701/15 | missing | 701/15 | 701/15 | 701/15 | 701/15 | 2 |
| dicom.pdu_len | 701/2 | missing | 701/2 | 701/2 | 701/2 | 701/2 | 6 |
| dicom.pdu_type | 701/1 | missing | 701/1 | 701/1 | 701/1 | 701/1 | 28 |
| dicom.pdv_context | 701/11 | missing | 701/11 | 701/11 | 701/11 | 701/11 | 1 |
| dicom.pdv_flags | 701/12 | missing | 701/12 | 701/12 | 701/12 | 701/12 | 1 |
| dicom.pdv_length | 701/10 | missing | 701/10 | 701/10 | 701/10 | 701/10 | 2 |
| dicom.proto_version | 701/3 | missing | 701/3 | 701/3 | 701/3 | 701/3 | 1 |
| dicom.status | 701/16 | missing | 701/16 | 701/16 | 701/16 | 701/16 | 2 |

### Build on X, load on Y: rules whose baked ids are wrong

Rows: the header the `.so` was compiled with. Columns: the libmmt_core it is loaded into. Cell: rules (of 96) with at least one missing pair, or a pair whose proto_id, att_id or dpi_type differs; 0 means every rule is safe.

| built with \ loaded into | fd93012d | 6b1c9f53 | v1.8.0 | v1.10.2 | v1.10.3 |
|---|---|---|---|---|---|
| committed-header | 30 | 0 | 0 | 0 | 0 |
| fd93012d | 0 | 0 | 0 | 0 | 0 |
| 6b1c9f53 | 30 | 0 | 0 | 0 | 0 |
| v1.8.0 | 30 | 0 | 0 | 0 | 0 |
| v1.10.2 | 30 | 0 | 0 | 0 | 0 |
| v1.10.3 | 30 | 0 | 0 | 0 | 0 |

### Affected rules

- built with **committed-header**, loaded into **fd93012d** (30 rules): 200.detect_invalid_pdu_type.xml (200), 201.detect_invalid_command_field.xml (201), 202.detect_anomalous_status.xml (202), 203.detect_invalid_status.xml (203), 204.detect_message_id_zero.xml (204), 205.detect_message_id_max.xml (205), 206.detect_invalid_data_set_type.xml (206), 207.detect_pdu_length_too_large.xml (207), 208.detect_pdu_length_zero.xml (208), 209.detect_invalid_protocol_version.xml (209), 210.detect_pdv_length_anomaly.xml (210), 211.detect_invalid_pdv_flags.xml (211), 212.detect_unexpected_cancel.xml (212), 213.detect_response_as_request.xml (213), 214.detect_unexpected_abort.xml (214), 215.detect_pdata_without_association.xml (215), 216.detect_assoc_after_data.xml (216), 217.detect_format_string_app_context.xml (217), 218.detect_path_traversal_sop_uid.xml (218), 219.detect_ae_title_overflow.xml (219), 220.detect_association_flood.xml (220), 221.detect_suspicious_ae_title.xml (221), 222.detect_patient_data_injection.xml (222), 223.detect_wildcard_query.xml (223), 224.detect_pdu_length_mismatch.xml (224), 225.detect_invalid_abstract_syntax.xml (225), 226.detect_release_abort_length.xml (226), 227.detect_oversized_associate.xml (227), 228.detect_ae_title_swap.xml (228), 229.detect_pdv_pdu_length_mismatch.xml (229)
- built with **6b1c9f53**, loaded into **fd93012d** (30 rules): 200.detect_invalid_pdu_type.xml (200), 201.detect_invalid_command_field.xml (201), 202.detect_anomalous_status.xml (202), 203.detect_invalid_status.xml (203), 204.detect_message_id_zero.xml (204), 205.detect_message_id_max.xml (205), 206.detect_invalid_data_set_type.xml (206), 207.detect_pdu_length_too_large.xml (207), 208.detect_pdu_length_zero.xml (208), 209.detect_invalid_protocol_version.xml (209), 210.detect_pdv_length_anomaly.xml (210), 211.detect_invalid_pdv_flags.xml (211), 212.detect_unexpected_cancel.xml (212), 213.detect_response_as_request.xml (213), 214.detect_unexpected_abort.xml (214), 215.detect_pdata_without_association.xml (215), 216.detect_assoc_after_data.xml (216), 217.detect_format_string_app_context.xml (217), 218.detect_path_traversal_sop_uid.xml (218), 219.detect_ae_title_overflow.xml (219), 220.detect_association_flood.xml (220), 221.detect_suspicious_ae_title.xml (221), 222.detect_patient_data_injection.xml (222), 223.detect_wildcard_query.xml (223), 224.detect_pdu_length_mismatch.xml (224), 225.detect_invalid_abstract_syntax.xml (225), 226.detect_release_abort_length.xml (226), 227.detect_oversized_associate.xml (227), 228.detect_ae_title_swap.xml (228), 229.detect_pdv_pdu_length_mismatch.xml (229)
- built with **v1.8.0**, loaded into **fd93012d** (30 rules): 200.detect_invalid_pdu_type.xml (200), 201.detect_invalid_command_field.xml (201), 202.detect_anomalous_status.xml (202), 203.detect_invalid_status.xml (203), 204.detect_message_id_zero.xml (204), 205.detect_message_id_max.xml (205), 206.detect_invalid_data_set_type.xml (206), 207.detect_pdu_length_too_large.xml (207), 208.detect_pdu_length_zero.xml (208), 209.detect_invalid_protocol_version.xml (209), 210.detect_pdv_length_anomaly.xml (210), 211.detect_invalid_pdv_flags.xml (211), 212.detect_unexpected_cancel.xml (212), 213.detect_response_as_request.xml (213), 214.detect_unexpected_abort.xml (214), 215.detect_pdata_without_association.xml (215), 216.detect_assoc_after_data.xml (216), 217.detect_format_string_app_context.xml (217), 218.detect_path_traversal_sop_uid.xml (218), 219.detect_ae_title_overflow.xml (219), 220.detect_association_flood.xml (220), 221.detect_suspicious_ae_title.xml (221), 222.detect_patient_data_injection.xml (222), 223.detect_wildcard_query.xml (223), 224.detect_pdu_length_mismatch.xml (224), 225.detect_invalid_abstract_syntax.xml (225), 226.detect_release_abort_length.xml (226), 227.detect_oversized_associate.xml (227), 228.detect_ae_title_swap.xml (228), 229.detect_pdv_pdu_length_mismatch.xml (229)
- built with **v1.10.2**, loaded into **fd93012d** (30 rules): 200.detect_invalid_pdu_type.xml (200), 201.detect_invalid_command_field.xml (201), 202.detect_anomalous_status.xml (202), 203.detect_invalid_status.xml (203), 204.detect_message_id_zero.xml (204), 205.detect_message_id_max.xml (205), 206.detect_invalid_data_set_type.xml (206), 207.detect_pdu_length_too_large.xml (207), 208.detect_pdu_length_zero.xml (208), 209.detect_invalid_protocol_version.xml (209), 210.detect_pdv_length_anomaly.xml (210), 211.detect_invalid_pdv_flags.xml (211), 212.detect_unexpected_cancel.xml (212), 213.detect_response_as_request.xml (213), 214.detect_unexpected_abort.xml (214), 215.detect_pdata_without_association.xml (215), 216.detect_assoc_after_data.xml (216), 217.detect_format_string_app_context.xml (217), 218.detect_path_traversal_sop_uid.xml (218), 219.detect_ae_title_overflow.xml (219), 220.detect_association_flood.xml (220), 221.detect_suspicious_ae_title.xml (221), 222.detect_patient_data_injection.xml (222), 223.detect_wildcard_query.xml (223), 224.detect_pdu_length_mismatch.xml (224), 225.detect_invalid_abstract_syntax.xml (225), 226.detect_release_abort_length.xml (226), 227.detect_oversized_associate.xml (227), 228.detect_ae_title_swap.xml (228), 229.detect_pdv_pdu_length_mismatch.xml (229)
- built with **v1.10.3**, loaded into **fd93012d** (30 rules): 200.detect_invalid_pdu_type.xml (200), 201.detect_invalid_command_field.xml (201), 202.detect_anomalous_status.xml (202), 203.detect_invalid_status.xml (203), 204.detect_message_id_zero.xml (204), 205.detect_message_id_max.xml (205), 206.detect_invalid_data_set_type.xml (206), 207.detect_pdu_length_too_large.xml (207), 208.detect_pdu_length_zero.xml (208), 209.detect_invalid_protocol_version.xml (209), 210.detect_pdv_length_anomaly.xml (210), 211.detect_invalid_pdv_flags.xml (211), 212.detect_unexpected_cancel.xml (212), 213.detect_response_as_request.xml (213), 214.detect_unexpected_abort.xml (214), 215.detect_pdata_without_association.xml (215), 216.detect_assoc_after_data.xml (216), 217.detect_format_string_app_context.xml (217), 218.detect_path_traversal_sop_uid.xml (218), 219.detect_ae_title_overflow.xml (219), 220.detect_association_flood.xml (220), 221.detect_suspicious_ae_title.xml (221), 222.detect_patient_data_injection.xml (222), 223.detect_wildcard_query.xml (223), 224.detect_pdu_length_mismatch.xml (224), 225.detect_invalid_abstract_syntax.xml (225), 226.detect_release_abort_length.xml (226), 227.detect_oversized_associate.xml (227), 228.detect_ae_title_swap.xml (228), 229.detect_pdv_pdu_length_mismatch.xml (229)

### Whole DPI registry (every protocol and attribute, not only the rules')

Counts of `to`. Protocols and attributes are counted separately; an attribute of a removed or added protocol counts as a removed or added attribute.

| from -> to | protocols | attributes | protocols added | protocols removed | attributes added | attributes removed | id changed | type changed |
|---|---|---|---|---|---|---|---|---|
| committed-header -> fd93012d | 669 | 7395 | 0 | 1 | 0 | 31 | 0 | 0 |
|  | removed: dicom.*, dicom.pdu_type, dicom.pdu_len, dicom.proto_version, dicom.called_ae_title, dicom.calling_ae_title, dicom.application_context, dicom.presentation_context, dicom.max_pdu_length, dicom.implementation_class_uid, dicom.pdv_length, dicom.pdv_context ... ||||||||
| fd93012d -> 6b1c9f53 | 670 | 7426 | 1 | 0 | 31 | 0 | 0 | 0 |
| 6b1c9f53 -> v1.8.0 | 672 | 7446 | 2 | 0 | 20 | 0 | 0 | 0 |
| v1.8.0 -> v1.10.2 | 679 | 7530 | 7 | 0 | 85 | 1 | 0 | 3 |
|  | type changed: quic_ietf.dst_conn_id MMT_STRING_DATA_POINTER->MMT_STRING_LONG_DATA, quic_ietf.src_conn_id MMT_STRING_DATA_POINTER->MMT_STRING_LONG_DATA, quic_ietf.token MMT_STRING_DATA_POINTER->MMT_STRING_LONG_DATA ||||||||
|  | removed: http.header ||||||||
| v1.10.2 -> v1.10.3 | 679 | 7530 | 0 | 0 | 0 | 0 | 0 | 0 |

### All pairs

<details><summary>98 pairs, proto_id/att_id/dpi_type per source, and the rule ids using each</summary>

| proto.att | committed-header | fd93012d | 6b1c9f53 | v1.8.0 | v1.10.2 | v1.10.3 | rules |
|---|---|---|---|---|---|---|---|
| arp.ar_op | 30/5/2 | 30/5/2 | 30/5/2 | 30/5/2 | 30/5/2 | 30/5/2 | 4,5 |
| arp.ar_sha | 30/6/6 | 30/6/6 | 30/6/6 | 30/6/6 | 30/6/6 | 30/6/6 | 4,5 |
| arp.ar_sip | 30/7/8 | 30/7/8 | 30/7/8 | 30/7/8 | 30/7/8 | 30/7/8 | 4,5 |
| arp.ar_tip | 30/9/8 | 30/9/8 | 30/9/8 | 30/9/8 | 30/9/8 | 30/9/8 | 4 |
| dicom.abstract_syntax | 701/19/27 | missing | 701/19/27 | 701/19/27 | 701/19/27 | 701/19/27 | 225 |
| dicom.affected_sop_class_uid | 701/17/27 | missing | 701/17/27 | 701/17/27 | 701/17/27 | 701/17/27 | 218 |
| dicom.application_context | 701/6/27 | missing | 701/6/27 | 701/6/27 | 701/6/27 | 701/6/27 | 217 |
| dicom.called_ae_title | 701/4/27 | missing | 701/4/27 | 701/4/27 | 701/4/27 | 701/4/27 | 219,221,228 |
| dicom.calling_ae_title | 701/5/27 | missing | 701/5/27 | 701/5/27 | 701/5/27 | 701/5/27 | 228 |
| dicom.command_field | 701/14/2 | missing | 701/14/2 | 701/14/2 | 701/14/2 | 701/14/2 | 201,212,213 |
| dicom.data_set_type | 701/21/2 | missing | 701/21/2 | 701/21/2 | 701/21/2 | 701/21/2 | 206 |
| dicom.message_id | 701/18/2 | missing | 701/18/2 | 701/18/2 | 701/18/2 | 701/18/2 | 204,205 |
| dicom.patient_name | 701/15/27 | missing | 701/15/27 | 701/15/27 | 701/15/27 | 701/15/27 | 222,223 |
| dicom.pdu_len | 701/2/3 | missing | 701/2/3 | 701/2/3 | 701/2/3 | 701/2/3 | 207,208,224,226,227,229 |
| dicom.pdu_type | 701/1/1 | missing | 701/1/1 | 701/1/1 | 701/1/1 | 701/1/1 | 28 rules |
| dicom.pdv_context | 701/11/1 | missing | 701/11/1 | 701/11/1 | 701/11/1 | 701/11/1 | 215 |
| dicom.pdv_flags | 701/12/1 | missing | 701/12/1 | 701/12/1 | 701/12/1 | 701/12/1 | 211 |
| dicom.pdv_length | 701/10/3 | missing | 701/10/3 | 701/10/3 | 701/10/3 | 701/10/3 | 210,229 |
| dicom.proto_version | 701/3/2 | missing | 701/3/2 | 701/3/2 | 701/3/2 | 701/3/2 | 209 |
| dicom.status | 701/16/2 | missing | 701/16/2 | 701/16/2 | 701/16/2 | 701/16/2 | 202,203 |
| dtls.client_hello_cipher_suite | 660/6/32 | 660/6/32 | 660/6/32 | 660/6/32 | 660/6/32 | 660/6/32 | 79 |
| dtls.p_data | 660/4097/5 | 660/4097/5 | 660/4097/5 | 660/4097/5 | 660/4097/5 | 660/4097/5 | 79 |
| dtls.packet_count | 660/4099/4 | 660/4099/4 | 660/4099/4 | 660/4099/4 | 660/4099/4 | 660/4099/4 | 79 |
| ethernet.dst | 99/2/6 | 99/2/6 | 99/2/6 | 99/2/6 | 99/2/6 | 99/2/6 | 4 |
| ethernet.packet_count | 99/4099/4 | 99/4099/4 | 99/4099/4 | 99/4099/4 | 99/4099/4 | 99/4099/4 | 4 |
| ethernet.proto | 99/1/2 | 99/1/2 | 99/1/2 | 99/1/2 | 99/1/2 | 99/1/2 | 11 |
| ethernet.src | 99/3/6 | 99/3/6 | 99/3/6 | 99/3/6 | 99/3/6 | 99/3/6 | 4 |
| ftp.packet_request | 117/28/31 | 117/28/31 | 117/28/31 | 117/28/31 | 117/28/31 | 117/28/31 | 48 |
| ftp.packet_request_parameter | 117/29/31 | 117/29/31 | 117/29/31 | 117/29/31 | 117/29/31 | 117/29/31 | 48 |
| gre.version | 137/9/2 | 137/9/2 | 137/9/2 | 137/9/2 | 137/9/2 | 137/9/2 | 18 |
| http.host | 153/3/29 | 153/3/29 | 153/3/29 | 153/3/29 | 153/3/29 | 153/3/29 | 38 |
| http.method | 153/1/29 | 153/1/29 | 153/1/29 | 153/1/29 | 153/1/29 | 153/1/29 | 15,33,34 |
| http.uri | 153/4/29 | 153/4/29 | 153/4/29 | 153/4/29 | 153/4/29 | 153/4/29 | 33,77 |
| http.user_agent | 153/7/29 | 153/7/29 | 153/7/29 | 153/7/29 | 153/7/29 | 153/7/29 | 15,34,77 |
| http2.header_length | 700/3/3 | 700/3/3 | 700/3/3 | 700/3/3 | 700/3/3 | 700/3/3 | 97 |
| http2.header_method | 700/2/1 | 700/2/1 | 700/2/1 | 700/2/1 | 700/2/1 | 700/2/1 | 96,97,98 |
| http2.p_payload | 700/4098/5 | 700/4098/5 | 700/4098/5 | 700/4098/5 | 700/4098/5 | 700/4098/5 | 98 |
| http2.payload_length | 700/16/3 | 700/16/3 | 700/16/3 | 700/16/3 | 700/16/3 | 700/16/3 | 98 |
| http2.type | 700/1/1 | 700/1/1 | 700/1/1 | 700/1/1 | 700/1/1 | 700/1/1 | 96 |
| icmp.packet_count | 163/4099/4 | 163/4099/4 | 163/4099/4 | 163/4099/4 | 163/4099/4 | 163/4099/4 | 51 |
| icmp.type | 163/1/1 | 163/1/1 | 163/1/1 | 163/1/1 | 163/1/1 | 163/1/1 | 20 |
| int.hop_switch_ids | 658/4/33 | 658/4/33 | 658/4/33 | 658/4/33 | 658/4/33 | 658/4/33 | 78 |
| int.packet_count | 658/4099/4 | 658/4099/4 | 658/4099/4 | 658/4099/4 | 658/4099/4 | 658/4099/4 | 78 |
| ip.client_addr | 178/19/8 | 178/19/8 | 178/19/8 | 178/19/8 | 178/19/8 | 178/19/8 | 79 |
| ip.client_port | 178/21/2 | 178/21/2 | 178/21/2 | 178/21/2 | 178/21/2 | 178/21/2 | 79 |
| ip.df_flag | 178/7/1 | 178/7/1 | 178/7/1 | 178/7/1 | 178/7/1 | 178/7/1 | 51,52,53 |
| ip.dst | 178/14/8 | 178/14/8 | 178/14/8 | 178/14/8 | 178/14/8 | 178/14/8 | 58 rules |
| ip.frag_offset | 178/9/2 | 178/9/2 | 178/9/2 | 178/9/2 | 178/9/2 | 178/9/2 | 9,21,22,23,24,25 |
| ip.identification | 178/5/2 | 178/5/2 | 178/5/2 | 178/5/2 | 178/5/2 | 178/5/2 | 21,22,23,24,25,52,75 |
| ip.ip_frag_packets_count | 178/23/4 | 178/23/4 | 178/23/4 | 178/23/4 | 178/23/4 | 178/23/4 | 8 |
| ip.mf_flag | 178/8/1 | 178/8/1 | 178/8/1 | 178/8/1 | 178/8/1 | 178/8/1 | 9,21,22,23,24,25,51,52,53,75 |
| ip.opts_type | 178/16/1 | 178/16/1 | 178/16/1 | 178/16/1 | 178/16/1 | 178/16/1 | 8,60 |
| ip.packet_count | 178/4099/4 | 178/4099/4 | 178/4099/4 | 178/4099/4 | 178/4099/4 | 178/4099/4 | 54,68,69,70,71,76 |
| ip.padding_check | 178/17/1 | 178/17/1 | 178/17/1 | 178/17/1 | 178/17/1 | 178/17/1 | 64 |
| ip.proto_id | 178/11/1 | 178/11/1 | 178/11/1 | 178/11/1 | 178/11/1 | 178/11/1 | 26,27,62 |
| ip.proto_ttl | 178/10/1 | 178/10/1 | 178/10/1 | 178/10/1 | 178/10/1 | 178/10/1 | 75 |
| ip.rf_flag | 178/6/1 | 178/6/1 | 178/6/1 | 178/6/1 | 178/6/1 | 178/6/1 | 65 |
| ip.server_addr | 178/20/8 | 178/20/8 | 178/20/8 | 178/20/8 | 178/20/8 | 178/20/8 | 79 |
| ip.server_port | 178/22/2 | 178/22/2 | 178/22/2 | 178/22/2 | 178/22/2 | 178/22/2 | 79 |
| ip.src | 178/13/8 | 178/13/8 | 178/13/8 | 178/13/8 | 178/13/8 | 178/13/8 | 88 rules |
| ip.tot_len | 178/4/2 | 178/4/2 | 178/4/2 | 178/4/2 | 178/4/2 | 178/4/2 | 9,24,25 |
| ip.version | 178/1/1 | 178/1/1 | 178/1/1 | 178/1/1 | 178/1/1 | 178/1/1 | 59 |
| ipv6.dst | 182/9/9 | 182/9/9 | 182/9/9 | 182/9/9 | 182/9/9 | 182/9/9 | 72 |
| ipv6.packet_count | 182/4099/4 | 182/4099/4 | 182/4099/4 | 182/4099/4 | 182/4099/4 | 182/4099/4 | 72 |
| ipv6.src | 182/8/9 | 182/8/9 | 182/8/9 | 182/8/9 | 182/8/9 | 182/8/9 | 72 |
| meta.packet_index | 1/10/4 | 1/10/4 | 1/10/4 | 1/10/4 | 1/10/4 | 1/10/4 | 98 |
| meta.packet_len | 1/4/3 | 1/4/3 | 1/4/3 | 1/4/3 | 1/4/3 | 1/4/3 | 11,51,53 |
| meta.proto_hierarchy | 1/5/10 | 1/5/10 | 1/5/10 | 1/5/10 | 1/5/10 | 1/5/10 | 73,207,209,221,227 |
| meta.utime | 1/3/11 | 1/3/11 | 1/3/11 | 1/3/11 | 1/3/11 | 1/3/11 | 95,96,220 |
| nas_5g.message_authentication_code | 904/5/3 | 904/5/3 | 904/5/3 | 904/5/3 | 904/5/3 | 904/5/3 | 90 |
| nas_5g.message_type | 904/2/1 | 904/2/1 | 904/2/1 | 904/2/1 | 904/2/1 | 904/2/1 | 91 |
| nas_5g.p_data | 904/4097/5 | 904/4097/5 | 904/4097/5 | 904/4097/5 | 904/4097/5 | 904/4097/5 | 90 |
| nas_5g.security_type | 904/3/1 | 904/3/1 | 904/3/1 | 904/3/1 | 904/3/1 | 904/3/1 | 90 |
| nas_5g.sequence_number | 904/6/1 | 904/6/1 | 904/6/1 | 904/6/1 | 904/6/1 | 904/6/1 | 90 |
| ngap.amf_ue_id | 903/3/4 | 903/3/4 | 903/3/4 | 903/3/4 | 903/3/4 | 903/3/4 | 90,91 |
| ngap.procedure_code | 903/1/2 | 903/1/2 | 903/1/2 | 903/1/2 | 903/1/2 | 903/1/2 | 91,93,94,95 |
| ngap.ran_ue_id | 903/4/4 | 903/4/4 | 903/4/4 | 903/4/4 | 903/4/4 | 903/4/4 | 91,94 |
| sctp.ch_type | 304/5/1 | 304/5/1 | 304/5/1 | 304/5/1 | 304/5/1 | 304/5/1 | 41,46 |
| sctp.dest_port | 304/2/2 | 304/2/2 | 304/2/2 | 304/2/2 | 304/2/2 | 304/2/2 | 41,46,92,93,94,95 |
| sctp.packet_count | 304/4099/4 | 304/4099/4 | 304/4099/4 | 304/4099/4 | 304/4099/4 | 304/4099/4 | 92 |
| sctp_data.data_ppid | 631/7/3 | 631/7/3 | 631/7/3 | 631/7/3 | 631/7/3 | 631/7/3 | 92,93 |
| sctp_data.data_stream | 631/5/2 | 631/5/2 | 631/5/2 | 631/5/2 | 631/5/2 | 631/5/2 | 91 |
| sctp_data.data_tsn | 631/4/3 | 631/4/3 | 631/4/3 | 631/4/3 | 631/4/3 | 631/4/3 | 90 |
| tcp.ack_nb | 354/4/3 | 354/4/3 | 354/4/3 | 354/4/3 | 354/4/3 | 354/4/3 | 6,84 |
| tcp.dest_port | 354/2/2 | 354/2/2 | 354/2/2 | 354/2/2 | 354/2/2 | 354/2/2 | 1,6,40,42,43,44,45,47 |
| tcp.fin | 354/7/1 | 354/7/1 | 354/7/1 | 354/7/1 | 354/7/1 | 354/7/1 | 28 |
| tcp.flags | 354/6/1 | 354/6/1 | 354/6/1 | 354/6/1 | 354/6/1 | 354/6/1 | 1,6,13,40,42,43,44,45,47,56,84 |
| tcp.p_data | 354/4097/5 | 354/4097/5 | 354/4097/5 | 354/4097/5 | 354/4097/5 | 354/4097/5 | 84 |
| tcp.p_payload | 354/4098/5 | 354/4098/5 | 354/4098/5 | 354/4098/5 | 354/4098/5 | 354/4098/5 | 54,68,69,70,71,72,76 |
| tcp.payload_len | 354/27/3 | 354/27/3 | 354/27/3 | 354/27/3 | 354/27/3 | 354/27/3 | 13 |
| tcp.psh | 354/10/1 | 354/10/1 | 354/10/1 | 354/10/1 | 354/10/1 | 354/10/1 | 28 |
| tcp.rst | 354/9/1 | 354/9/1 | 354/9/1 | 354/9/1 | 354/9/1 | 354/9/1 | 47 |
| tcp.seq_nb | 354/3/3 | 354/3/3 | 354/3/3 | 354/3/3 | 354/3/3 | 354/3/3 | 6,84 |
| tcp.src_port | 354/1/2 | 354/1/2 | 354/1/2 | 354/1/2 | 354/1/2 | 354/1/2 | 1,47,84 |
| tcp.tcp_session_payload_up | 354/24/5 | 354/24/5 | 354/24/5 | 354/24/5 | 354/24/5 | 354/24/5 | 67 |
| tcp.urg | 354/12/1 | 354/12/1 | 354/12/1 | 354/12/1 | 354/12/1 | 354/12/1 | 28,66 |
| tcp.urg_pointer | 354/17/2 | 354/17/2 | 354/17/2 | 354/17/2 | 354/17/2 | 354/17/2 | 84 |
| udp.dest_port | 376/2/2 | 376/2/2 | 376/2/2 | 376/2/2 | 376/2/2 | 376/2/2 | 27 |

</details>

### `abi-layout.sh`

Run as `tools/dpi-id-stability/abi-layout.sh $(git tag -l 'v1.2.*' | sort -V) 97441d79 3904b83c 4e21362d`
(the tags, then three fork commits), on aarch64:

```
v1.2.0   16d8b2bd7388 REQUIRE_PLUGIN=1.2.0
v1.2.1   16d8b2bd7388 REQUIRE_PLUGIN=1.2.0
v1.2.2   16d8b2bd7388 REQUIRE_PLUGIN=1.2.0
v1.2.4   4e03282b759a REQUIRE_PLUGIN=1.2.0
    < enums FSM_EVENT_TYPE_TIMEOUT=0 FSM_ACTION_DO_NOTHING=0 FSM_ACTION_CREATE_INSTANCE=1 FSM_ACTION_RESET_TIMER=2 NUMERIC=0 STRING=1 VOID=2 RULE_TYPE_ATTACK=0 RULE_TYPE_SECURITY=1 RULE_TYPE_EVASION=2 RULE_TYPE_TEST=3
    > enums FSM_EVENT_TYPE_TIMEOUT=0 FSM_ACTION_DO_NOTHING=0 FSM_ACTION_CREATE_INSTANCE=1 FSM_ACTION_RESET_TIMER=2 MMT_SEC_MSG_DATA_TYPE_NUMERIC=0 MMT_SEC_MSG_DATA_TYPE_STRING=1 MMT_SEC_MSG_DATA_TYPE_BINARY=2 RULE_TYPE_ATTACK=0 RULE_TYPE_SECURITY=1 RULE_TYPE_EVASION=2 RULE_TYPE_TEST=3
v1.2.5   4e03282b759a REQUIRE_PLUGIN=1.2.0
v1.2.6   6a95e6b901cb REQUIRE_PLUGIN=1.2.7
    < message_t 64 counter@0:8 timestamp@8:8 elements@16:8 elements_count@24:2 hash@32:8
    > message_t 128 counter@0:8 timestamp@8:8 elements@24:8 elements_count@32:2 hash@40:8
v1.2.7   6a95e6b901cb REQUIRE_PLUGIN=1.2.7
v1.2.8   6a95e6b901cb REQUIRE_PLUGIN=1.2.7
v1.2.9   6a95e6b901cb REQUIRE_PLUGIN=1.2.7
v1.2.10  6a95e6b901cb REQUIRE_PLUGIN=1.2.7
v1.2.11  6a95e6b901cb REQUIRE_PLUGIN=1.2.7
v1.2.12  6a95e6b901cb REQUIRE_PLUGIN=1.2.7
v1.2.13  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
    < message_t 128 counter@0:8 timestamp@8:8 elements@24:8 elements_count@32:2 hash@40:8
    > message_t 128 counter@0:8 timestamp@8:8 elements@24:8 elements_count@32:2 hash@34:32
v1.2.14  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
v1.2.15  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
v1.2.16  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
v1.2.17  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
v1.2.18  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
v1.2.19  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
v1.2.20  a9728e9cf6fa REQUIRE_PLUGIN=1.2.7
97441d79 d0f0681b5ed9 REQUIRE_PLUGIN=1.2.7
    < rule_engine_t not read
    > rule_engine_t 112 msg_values@96:8
3904b83c 1b7612cea617 REQUIRE_PLUGIN=1.2.21
    < rule_info_t 96 id@0:4 type_id@4:4 type_string@8:8 description@16:8 if_satisfied@24:8 if_not_satisfied@32:8 proto_atts_count@40:1 events_count@41:1 proto_atts@48:8 proto_atts_events@56:8 excluded_filter@64:8 create_instance@72:8 hash_message@80:8 version@88:8
    > rule_info_t 104 id@0:4 type_id@4:4 type_string@8:8 description@16:8 if_satisfied@24:8 if_not_satisfied@32:8 proto_atts_count@40:1 events_count@41:1 proto_atts@48:8 proto_atts_events@56:8 excluded_filter@64:8 create_instance@72:8 hash_message@80:8 version@88:8 instance_keys@96:8
    > fsm_instance_key_component_t 12 msg_att_index@0:2 his_event_id@2:2 his_att_index@4:2 data_type@8:4
    > fsm_instance_key_t 16 components_count@0:1 components@8:8
    < rule_engine_t 112 msg_values@96:8
    > rule_engine_t 136 msg_values@120:8
4e21362d 66f8656a8e4b REQUIRE_PLUGIN=1.2.22
    < rule_engine_t 136 msg_values@120:8
    > rule_engine_t opaque mmt_sec_rule_engine_get_msg_values
```

97441d79, 3904b83c and 4e21362d are not tags: 97441d79 is the fork before
the #51 instance index (stamped 1.2.20, with `REQUIRE_PLUGIN` 1.2.7, and the
first tree whose guards read `rule_engine_t.msg_values`); 3904b83c is the
fork after it (PR #55, stamped 1.2.21); 4e21362d is the fork after #56
(stamped 1.2.22), where the guards call `mmt_sec_rule_engine_get_msg_values`.
Since #56 the probe also prints `rule_info_t.instance_keys`, the fields of
`mmt_array_t`, the instance-key structs (from 3904b83c on), the fsm structs
(`fsm_t` by field only), `mmt_memory_t`, the enum values the generated code
compiles in, and what the guards read of `rule_engine_t`, so its hashes
differ from those of the A0 run (the v1.2.20 layout was `4e1647eaf219`).
The fsm structs, `mmt_memory_t` and the enum values did not change at any
tag; at v1.2.4 the data types were only renamed (`NUMERIC, STRING, VOID` to
`MMT_SEC_MSG_DATA_TYPE_NUMERIC, _STRING, _BINARY`, same values).
