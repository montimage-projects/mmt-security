# Unreleased
- packaging: `make rpm` works again — its `%prep` copied the package payload from a relative `TMP_DIR`, which is not found from the spec's own directory; it now uses an absolute path (fork PR #34)
- packaging: the binaries no longer link `libmmt_tcpip.so` (nothing used it, and it broke `make` on RHEL/Rocky where gcc links `--no-as-needed`); the deb declares the shared libraries of its binaries via `dpkg-shlibdeps` (the libxml2 soname differs by release) and the real `Architecture:`; `make rpm`'s `mkdir -p` and spec writing work where `/bin/sh` is dash; `check-build-info` compares `build.target` to the triplet the compiler's predefined macros give, since `gcc -dumpmachine` can add a vendor part (Red Hat's `aarch64-redhat-linux` vs `aarch64-linux-gnu`) (fork issue #35)
- mmt_sec_standalone: new option `-R` enables IP defragmentation and TCP reassembly in MMT-DPI, so rules on `tcp.tcp_session_payload_up`/`tcp.tcp_session_payload_down` (e.g., rule 67, EICAR split over TCP segments) can fire. It is off by default: it costs memory (MMT-DPI keeps each TCP flow's payload), and a reassembled stream that does not fit in `input.max_message_size` is skipped, with one warning per run and a count at the end (see readme.md). Without `-R`, `-v` prints a hint when such a rule is loaded (Montimage/mmt-security#42)
- engine: rules testing a TCP flag attribute equal to 0 (e.g., `tcp.flags == 0`, rule 42 TCP NULL scan) now fire; zero-valued TCP flags were dropped (Montimage/mmt-security#28)
- compile_rule: stricter `delay_min`, `delay_max`, `counter_min` and `counter_max` values. A value must be a non-negative integer, with an optional leading `+`, optionally followed by one `+` or `-` that makes the bound strict (e.g., `5`, `+5`, `0+`, `6-`). Values such as `"0.5"`, `" 0"`, `"0++"` or `"1s"` were silently read as something else; a rule using them now fails to compile, with a message naming the attribute and its value. All rules shipped in rules/ compile as before. Third-party rules may need fixing (Montimage/mmt-security#52)
- compile_rule: no longer crashes (stack overflow) when it stops on an error in a rule file, and stops at the end of an unterminated string constant (Montimage/mmt-security#52)
- compile_rule: exits with a non-zero status when gcc fails to compile the generated code; it used to exit 0 (Montimage/mmt-security#52)
- CI builds and checks against MMT-DPI v1.10.3 (was 6b1c9f5, v1.7.10 plus 36 commits); v1.10.0 to v1.10.2 lose the TCP payload of reassembled IPv4 fragments, so `make check` 19.SQLI fails with them (Montimage/mmt-security#18)
- rules 230 and 231 (in rules/properties_all) for OCPP 1.6-J: Heartbeat flooding and SetChargingProfile limit above the site maximum; they need the OCPP 1.6-J protocol plugin of mmt-plugin-generator (doc/rule.md, section 7); their alerts carry ip.src, ip.dst, tcp.src_port and tcp.dest_port
- packaging: the deb (`make deb`) now depends on `mmt-dpi (>= 1.10.3)`, which it did not before, and the rpm (`make rpm`) requires `mmt-dpi >= 1.10.3` (was 1.6.9). The DICOM rules need MMT-DPI 1.9.0 or later, which bounds `tcp.payload_len` by the captured bytes; 1.10.3 is the release CI tests. The version is `MIN_DPI_VERSION` in the Makefile
- rules 206 (invalid DICOM data set type) and 212 (unexpected DICOM C-CANCEL) are disabled: they are moved out of rules/ and kept in rules/properties_all, because they alert on normal traffic. Any Command Data Set Type other than 0x0101 means a data set is present (PS3.7 E.1), so 206 alerted on every C-STORE and C-FIND request; C-CANCEL is a standard DIMSE operation, so 212 alerted on every cancelled query. They are no longer in the deb and rpm packages (fork issue #27)

# Version 1.2.20 (05 Nov 2026)
- fixed bugs
- new rules for DICOM, RDP honepot

# Version 1.2.19 (15 June 2023)
- minor update in rules 96,97 and 98 concerining HTTP2 attacks detection

# Version 1.2.18 (03 June 2023)
- Add security rule 98 to detect attacks concerning HTTP2
- Add warning messages when DPI payload points to outside of packet data
- Print timeval in alert messages

# Version 1.2.17 (17 May 2023)
- Add 2 security rules, 96, 97 to detect attacks concerning HTTP2

# Version 1.2.16 (23 Mar 2023)
- Add prefix`MMT_SEC_` to the env variable in rule 95
- Add security rule to detect Slowloris DoS attack

# Version 1.2.15 (06 Jan 2023)
- Add two rules, 94 and 95, to detect DoS in 5G control plane traffic