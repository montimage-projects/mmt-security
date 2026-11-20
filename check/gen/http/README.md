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
                                       # 98.http2_state_evasion, 98.http2_fuzzing_benign_json

`gen_http1.py` and `gen_h2.py` come from fork PR #12, `gen_review.py` from the
fixes of its review. Each script comments every case: what it tests, and
whether the rule must alert.

The expected files list only the alerts of the rules a capture tests, so
`make check` ignores the alerts of the other rules on it.

`check/h2_thread_leak.sh` (outside `make check`, it needs valgrind) runs rules
97 and 98 with 2 verification threads (`-c`) and fails if their per-thread
state leaks at exit.
