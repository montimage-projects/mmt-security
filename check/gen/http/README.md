# HTTP and HTTP/2 check captures

Generators of the captures of the HTTP rules 33, 38, 69, 70, 71, 77 and the
HTTP/2 rules 97, 98. Every capture is crafted with scapy, without randomness
(the 5Greplay-like tails of `98.http2_fuzzing.pcap` use a fixed seed), so a run
rebuilds the committed files byte for byte:

    python3 gen_http1.py ../../pcap    # 33.38.trojan_wannacry, 69.70.http_double_encoding,
                                       # 71.http_version, 77.log4shell_variants
    python3 gen_h2.py ../../pcap       # 97.http2_hpack_bomb, 98.http2_fuzzing
    python3 gen_review.py ../../pcap   # 33.trojan_generic_uris_benign, 71.http_body_continuation,
                                       # 97.http2_state_evasion, 97.http2_hpack_table_size_zero,
                                       # 98.http2_state_evasion, 98.http2_fuzzing_benign_json,
                                       # 97.98.http2_conn_table, 97.98.http2_tcp_flags

`gen_http1.py` and `gen_h2.py` come from fork PR #12, `gen_review.py` from the
fixes of its two reviews. Each script comments every case: what it tests, and
whether the rule must alert.

The expected files list only the alerts of the rules a capture tests, so
`make check` ignores the alerts of the other rules on it.

`97.98.http2_conn_table` runs with `MMT_SEC_HTTP2_SEED=1`, from
`check/pcap/97.98.http2_conn_table.env` (`make check` reads the environment
variables of a capture from `check/pcap/X.env`): with this seed, the
connections of each of its cases fall in one set of the connection table of
rules 97 and 98, so the capture tests the ways and the LRU replacement.
`h2_set()` in `gen_review.py` computes the set of a connection.

`97.98.http2_tcp_flags` tests when rules 97 and 98 take a segment that
starts with the connection preface for a new connection on the same 4-tuple:
after a FIN or an RST of the client at its next sequence number, or a SYN-ACK
of the server, but not after a SYN alone, an RST or a FIN at another sequence
number, a FIN of the server, or a SYN-ACK for another sequence number.

`check/h2_thread_leak.sh` runs rules 97 and 98 with 2 verification threads
(`-c`) under valgrind and fails if their per-thread state leaks at exit. It is
outside `make check`, as it needs valgrind: `make check-valgrind` runs it, and
so does the CI after `make check`.
