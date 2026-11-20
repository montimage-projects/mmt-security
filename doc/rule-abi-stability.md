# Rule `.so` stability across mmt-dpi versions (A0)

This report measures whether a compiled rule (`rules/*.so`) built against one
mmt-dpi can be loaded safely into another. It also says whether the rule ABI
changed between mmt-security tags. It is the A0 experiment of Track A (fork
issue #5). The build-info, bundle and loader-check work builds on it.

Measured on 2026-11-20 on `main` at `0e2f9cb`, in `ubuntu:24.04` containers (aarch64,
gcc 13.3.0). The measurements can be reproduced with:

```sh
tools/dpi-id-stability/run.sh          # DPI ids: 5 mmt-dpi builds, ~10 min, docker, no sudo
tools/dpi-id-stability/abi-layout.sh   # rule ABI struct layouts at every v1.2.* tag
```

## Verdict

- **No protocol or attribute id changed** between the mmt-dpi versions measured
  (fd93012d, 6b1c9f53, v1.8.0, v1.10.2, v1.10.3). This holds for the 96
  (proto, att) pairs used by the 95 rules, and for the whole DPI registry
  (679 protocols and 7530 attributes in v1.10.3). The same goes for the
  attribute data types (`dpi_type`) the rules use, and for the `data_types`
  enum.
- So a rule `.so` built against any of 6b1c9f53, v1.8.0, v1.10.2, v1.10.3 or the
  committed header reads the right attributes on any of them: **0 of 95 rules
  are affected**.
- Pairs do go missing. The 30 DICOM rules (200-229) use `dicom.*`, which
  fd93012d does not have. Loaded into such a DPI, those rules register unknown
  ids (`register_extraction_attribute` fails silently,
  `src/main_sec_standalone.c:189-200`) and never fire. Nothing logs it.
- Between releases the registry gains attributes (+22 from 6b1c9f53 to 1.8.0,
  +92 from 1.8.0 to 1.10.2), loses one (`http.header` is gone in 1.10.x), and
  changes 3 attribute types (`quic_ietf.{dst_conn_id,src_conn_id,token}`, in
  1.10.x). No rule uses these today, but nothing protects a future rule
  from them.
- Stability holds by convention only. Nothing in mmt-dpi or mmt-security enforces
  it, and the loader checks only the mmt-security version index
  (`src/lib/plugins_engine.c:94-104`).

## How the ids get into a rule `.so`

1. `compile_rule` resolves each `proto.att` of a rule to numbers when it parses
   the rule (`src/lib/expression.c:94-96`: `get_protocol_id_by_name`,
   `get_attribute_id_by_protocol_id_and_attribute_name`,
   `get_attribute_data_type`).
2. Those functions are **not** the ones in `libmmt_core`. They are `static inline`
   lookups over a table in `src/dpi/mmt_dpi.h` (`src/main_gen_dpi.c:162-216`), a
   header generated from one mmt-dpi build by `gen_dpi_header` and **committed to
   the repository**.
3. `gen_code.c` writes the numbers into the generated C
   (`src/lib/gen_code.c:535`, `.proto_id = ..., .att_id = ..., .dpi_type = ...`).
   They are compiled into the `.so`.
4. At run time the engine registers those numbers with the running `libmmt_core`
   (`src/main_sec_standalone.c:189-224`). Nothing resolves the names again.

The Makefile regenerates the header only when it is missing
(`$(MMT_DPI_HEADER)` target). Hence:

- a plain `make` (the mmt-stack image, most local builds) bakes the ids of the
  **committed header**, whatever mmt-dpi is installed;
- `make clean-all && make` (upstream CI) regenerates the header from the
  installed mmt-dpi and bakes its ids.

The committed header starts with `using MMT-DPI v1.7.10 (fd93012d)`, but its table
is identical to that of 6b1c9f53 (all 8096 entries; it has DICOM, which fd93012d
lacks). It was probably generated from a fd93012d tree with the DICOM branch
merged in.

Because `gen_code.c` includes that header, `mmt_version()` in
`src/lib/gen_code.c:582` is the header's too. Every rule built with plain `make`
reports `dpi version 1.7.10 (fd93012d)` in `rule_info`, even when it was built
against DPI 1.10.3. Checked with `compile_rule rules/11.ip_size.xml` in an
ubuntu:24.04 container with the v1.10.3 `.deb`s. Today's `.dpi` field therefore
tells you where the ids came from, not what was installed.

## Method

`tools/dpi-id-stability/run.sh` does this for each mmt-dpi ref, in a fresh
`ubuntu:24.04` container:

1. It builds mmt-dpi from source at that commit, from a clone of
   https://github.com/Montimage/mmt-dpi, and installs it in the container.
2. It builds `compile_rule` twice: with the committed `src/dpi/mmt_dpi.h`, and
   with a header regenerated from this DPI (`make gen_dpi`, as `make clean-all`
   does).
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

Each cell counts the rules (of 95) that have at least one wrong or missing id
when a `.so` built with the row's header is loaded into the column's
`libmmt_core`.

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
(`Error 2: Protocol dicom has not implemented yet`). With the 65 rules it can
build, a fd93012d `.so` is safe on every later version.

### Whole DPI registry

| from -> to | protocols | attributes | removed | added | id changed | type changed |
|---|---|---|---|---|---|---|
| committed header -> fd93012d | 669 | 7395 | 32 (DICOM) | 0 | 0 | 0 |
| fd93012d -> 6b1c9f53 | 670 | 7426 | 0 | 32 (DICOM) | 0 | 0 |
| 6b1c9f53 -> v1.8.0 | 672 | 7446 | 0 | 22 | 0 | 0 |
| v1.8.0 -> v1.10.2 | 679 | 7530 | 1 (`http.header`) | 92 | 0 | 3 (`quic_ietf.*`) |
| v1.10.2 -> v1.10.3 | 679 | 7530 | 0 | 0 | 0 | 0 |

The `data_types` enum (`types_defs.h`, 35 values) is identical in all five, and
matches the copy in `src/main_gen_dpi.c`.

### Id assumptions outside the rules

These are not baked into rule `.so` files, but they assume ids:

- `src/lib/message_t.c:158` hardcodes `proto_id == 354` (TCP) and
  `6 <= att_id <= 14` (`flags`, `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`,
  `cwr`). This drops zero-valued TCP flags. Both numbers hold in all five
  versions measured, but a renumbered TCP would silently break every flag rule.
  It is fixed separately under Montimage#28 and is not changed here.
- `src/main_sec_standalone.c:217-221` and `src/lib/dpi_message_t.h:112-161` use
  `PROTO_TCP`, `PROTO_IP`, `TCP_PAYLOAD_LEN`, `IP_OPTS` and so on. They come from
  the installed mmt-dpi headers when the engine is built, so they always match
  the DPI the engine is linked against.
- `src/main_gen_dpi.c:26-60` keeps its own copy of the `data_types` names, by
  index. It matches all five versions.

## Rule ABI across mmt-security tags

A rule `.so` shares these with the engine: `rule_info_t`, `proto_attribute_t` and
`rule_version_info_t` (`src/lib/plugin_header.h`). Through the inline helpers it
also shares `message_t` and `message_element_t` (`src/lib/message_t.h`, read by
`get_element_data_message_t`), `mmt_array_t`, and the FSM structs of
`src/lib/mmt_fsm.h`. `tools/dpi-id-stability/abi-layout.sh` compiles a
`sizeof`/`offsetof` probe against `src/lib` of every v1.2.* tag:

| tags | rule_info_t, proto_attribute_t, rule_version_info_t | message_t | REQUIRE_PLUGIN |
|---|---|---|---|
| v1.2.0 - v1.2.5 | unchanged | 64 bytes, `elements@16`, `hash` u64 | 1.2.0 |
| v1.2.6 - v1.2.12 | unchanged | 128 bytes, `flow_id` and `user_data` added, `elements@24` | 1.2.7 |
| v1.2.13 - v1.2.20 | unchanged | `hash` becomes `mmt_bit_t` (32 bytes, at 34) | 1.2.7 |

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

## Recommendations

### For the build info (fork issue #6)

- **Hash only the pairs the rule uses, not the whole registry.** The registry
  changed at 4 of the 5 steps measured while no id moved. A whole-registry
  hash would flag every release even though every rule was safe. Hash the
  sorted `proto, proto_id, att, att_id, dpi_type` tuples the `.so` bakes in, and
  include `dpi_type`: types did change in 1.10.x.
- Also store the tuples themselves, so the loader can re-resolve each one by
  name and name the pair that differs.
- Record where the ids came from (the header's `mmt_version()`) and the
  installed `libmmt_core` version separately. A plain `make` makes them differ.
- Store a rule ABI hash over the `sizeof`/`offsetof` layout of the shared structs
  above, next to `REQUIRE_PLUGIN`. It would have caught v1.2.13.

### Default policy for the loader check (fork issue #8)

| condition | result |
|---|---|
| rule ABI hash differs from the engine's | FAIL |
| any (proto, att) of the rule does not resolve in the running `libmmt_core` (removed attribute, missing plugin: the DICOM case) | FAIL |
| any pair resolves to a different `proto_id`/`att_id` than the baked one | FAIL |
| any pair has a different `dpi_type` (the `quic_ietf` case) | FAIL |
| all ids and types match, but the DPI version or commit differs | WARN |
| no build info (a `.so` built before #6) | WARN, then fall back to re-resolving `rule_info_t.proto_atts` by name |
| everything matches | OK |

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
  Regenerating it (or building it at `make` time) would make the reported DPI
  version true.

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

- 95 rule files, 95 rules (properties), 96 distinct (proto, att) pairs.
- compile_rule cannot encode 30 rule file(s) with the regenerated header of fd93012d (200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229): `HALT_SEC: Error 2: Protocol dicom has not implemented yet.`

### Regenerated header vs. libmmt_core at run time

- fd93012d: all 96 pairs agree
- 6b1c9f53: all 96 pairs agree
- v1.8.0: all 96 pairs agree
- v1.10.2: all 96 pairs agree
- v1.10.3: all 96 pairs agree

### (proto, att) pairs whose ids differ

16 of 96 pairs differ (an id changes or the pair is missing) across the sources; 0 change dpi_type.

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

Rows: the header the `.so` was compiled with. Columns: the libmmt_core it is loaded into. Cell: rules (of 95) with at least one wrong or missing id; 0 means every rule is safe.

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

| from -> to | protocols | attributes | removed | added | id changed | type changed |
|---|---|---|---|---|---|---|
| committed-header -> fd93012d | 669 | 7395 | 32 | 0 | 0 | 0 |
|  | removed: dicom.*, dicom.pdu_type, dicom.pdu_len, dicom.proto_version, dicom.called_ae_title, dicom.calling_ae_title, dicom.application_context, dicom.presentation_context, dicom.max_pdu_length, dicom.implementation_class_uid, dicom.pdv_length, dicom.pdv_context ... ||||||
| fd93012d -> 6b1c9f53 | 670 | 7426 | 0 | 32 | 0 | 0 |
| 6b1c9f53 -> v1.8.0 | 672 | 7446 | 0 | 22 | 0 | 0 |
| v1.8.0 -> v1.10.2 | 679 | 7530 | 1 | 92 | 0 | 3 |
|  | type changed: quic_ietf.dst_conn_id MMT_STRING_DATA_POINTER->MMT_STRING_LONG_DATA, quic_ietf.src_conn_id MMT_STRING_DATA_POINTER->MMT_STRING_LONG_DATA, quic_ietf.token MMT_STRING_DATA_POINTER->MMT_STRING_LONG_DATA ||||||
|  | removed: http.header ||||||
| v1.10.2 -> v1.10.3 | 679 | 7530 | 0 | 0 | 0 | 0 |

### All pairs

<details><summary>96 pairs, proto_id/att_id/dpi_type per source, and the rule ids using each</summary>

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
| dtls.packet_count | 660/4099/4 | 660/4099/4 | 660/4099/4 | 660/4099/4 | 660/4099/4 | 660/4099/4 | 79 |
| dtls.version | 660/2/2 | 660/2/2 | 660/2/2 | 660/2/2 | 660/2/2 | 660/2/2 | 79 |
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
| ip.dst | 178/14/8 | 178/14/8 | 178/14/8 | 178/14/8 | 178/14/8 | 178/14/8 | 57 rules |
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
| ip.src | 178/13/8 | 178/13/8 | 178/13/8 | 178/13/8 | 178/13/8 | 178/13/8 | 87 rules |
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
| tcp.ack_nb | 354/4/3 | 354/4/3 | 354/4/3 | 354/4/3 | 354/4/3 | 354/4/3 | 6 |
| tcp.dest_port | 354/2/2 | 354/2/2 | 354/2/2 | 354/2/2 | 354/2/2 | 354/2/2 | 1,40,42,43,44,45,47 |
| tcp.fin | 354/7/1 | 354/7/1 | 354/7/1 | 354/7/1 | 354/7/1 | 354/7/1 | 28 |
| tcp.flags | 354/6/1 | 354/6/1 | 354/6/1 | 354/6/1 | 354/6/1 | 354/6/1 | 1,6,13,40,42,43,44,45,47,56 |
| tcp.p_payload | 354/4098/5 | 354/4098/5 | 354/4098/5 | 354/4098/5 | 354/4098/5 | 354/4098/5 | 54,68,69,70,71,72,76 |
| tcp.payload_len | 354/27/3 | 354/27/3 | 354/27/3 | 354/27/3 | 354/27/3 | 354/27/3 | 13 |
| tcp.psh | 354/10/1 | 354/10/1 | 354/10/1 | 354/10/1 | 354/10/1 | 354/10/1 | 28 |
| tcp.rst | 354/9/1 | 354/9/1 | 354/9/1 | 354/9/1 | 354/9/1 | 354/9/1 | 47 |
| tcp.seq_nb | 354/3/3 | 354/3/3 | 354/3/3 | 354/3/3 | 354/3/3 | 354/3/3 | 6 |
| tcp.src_port | 354/1/2 | 354/1/2 | 354/1/2 | 354/1/2 | 354/1/2 | 354/1/2 | 1,47 |
| tcp.tcp_session_payload_up | 354/24/5 | 354/24/5 | 354/24/5 | 354/24/5 | 354/24/5 | 354/24/5 | 67 |
| tcp.urg | 354/12/1 | 354/12/1 | 354/12/1 | 354/12/1 | 354/12/1 | 354/12/1 | 28,66 |
| udp.dest_port | 376/2/2 | 376/2/2 | 376/2/2 | 376/2/2 | 376/2/2 | 376/2/2 | 27 |

</details>

### `abi-layout.sh`

```
v1.2.0   258c7ee2bc05 REQUIRE_PLUGIN=1.2.0
v1.2.1   258c7ee2bc05 REQUIRE_PLUGIN=1.2.0
v1.2.2   258c7ee2bc05 REQUIRE_PLUGIN=1.2.0
v1.2.4   258c7ee2bc05 REQUIRE_PLUGIN=1.2.0
v1.2.5   258c7ee2bc05 REQUIRE_PLUGIN=1.2.0
v1.2.6   33532676bdd5 REQUIRE_PLUGIN=1.2.7
    < message_t 64 counter@0:8 timestamp@8:8 elements@16:8 elements_count@24:2 hash@32:8
    > message_t 128 counter@0:8 timestamp@8:8 elements@24:8 elements_count@32:2 hash@40:8
v1.2.7   33532676bdd5 REQUIRE_PLUGIN=1.2.7
v1.2.8   33532676bdd5 REQUIRE_PLUGIN=1.2.7
v1.2.9   33532676bdd5 REQUIRE_PLUGIN=1.2.7
v1.2.10  33532676bdd5 REQUIRE_PLUGIN=1.2.7
v1.2.11  33532676bdd5 REQUIRE_PLUGIN=1.2.7
v1.2.12  33532676bdd5 REQUIRE_PLUGIN=1.2.7
v1.2.13  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
    < message_t 128 counter@0:8 timestamp@8:8 elements@24:8 elements_count@32:2 hash@40:8
    > message_t 128 counter@0:8 timestamp@8:8 elements@24:8 elements_count@32:2 hash@34:32
v1.2.14  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
v1.2.15  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
v1.2.16  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
v1.2.17  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
v1.2.18  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
v1.2.19  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
v1.2.20  4e1647eaf219 REQUIRE_PLUGIN=1.2.7
```
