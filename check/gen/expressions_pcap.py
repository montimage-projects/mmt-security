#!/usr/bin/env python3
"""Generate check/expressions/expressions.pcap, the capture of check/check-expressions.sh.

Usage: python3 check/gen/expressions_pcap.py OUTPUT_DIR   (needs scapy)

The output is deterministic (fixed timestamps). From 10.0.0.1 to 10.0.0.2:
- three UDP datagrams, each with 20 bytes of payload (udp.len - 8 = 20), whose
  udp.dest_port - udp.src_port is 10, 50 and 20 (ports 1000->1010, 1000->1050,
  1000->1020);
- six HTTP/1.1 requests, each on its own TCP connection to port 80
  (handshake, request, response): GET, HEAD and POST with
  "User-Agent: check", then PUT with "User-Agent: AAAA", DELETE with
  "User-Agent: a" and OPTIONS with "User-Agent: zzzzzzz" — the three last pin
  the mmt_mem_cmp order of rule 9017: PUT (3) < AAAA (4) by size though "PUT"
  > "AAAA" by strcmp, DELETE (6) > a (1) by size though "DELETE" < "a" by
  strcmp, and OPTIONS (7) < zzzzzzz (7) on the memcmp of two 7-byte strings.
"""
import sys
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

T0 = 1795200000.0
CLI, SRV = "10.0.0.1", "10.0.0.2"
pkts = []
t = 0.0


def add(p):
    global t
    q = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / p
    q.time = T0 + t
    pkts.append(q)
    t += 0.01


for dport in (1010, 1050, 1020):
    add(IP(src=CLI, dst=SRV) / UDP(sport=1000, dport=dport) / Raw(b"x" * 20))

for i, (method, agent) in enumerate((("GET", "check"), ("HEAD", "check"), ("POST", "check"),
                                     ("PUT", "AAAA"), ("DELETE", "a"), ("OPTIONS", "zzzzzzz"))):
    sp = 40000 + i
    req = (f"{method} /index.html HTTP/1.1\r\nHost: {SRV}\r\nUser-Agent: {agent}\r\n"
           + ("Content-Length: 0\r\n" if method == "POST" else "") + "\r\n").encode()
    res = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    add(IP(src=CLI, dst=SRV) / TCP(sport=sp, dport=80, flags="S", seq=100))
    add(IP(src=SRV, dst=CLI) / TCP(sport=80, dport=sp, flags="SA", seq=500, ack=101))
    add(IP(src=CLI, dst=SRV) / TCP(sport=sp, dport=80, flags="A", seq=101, ack=501))
    add(IP(src=CLI, dst=SRV) / TCP(sport=sp, dport=80, flags="PA", seq=101, ack=501) / Raw(req))
    add(IP(src=SRV, dst=CLI) / TCP(sport=80, dport=sp, flags="PA", seq=501, ack=101 + len(req)) / Raw(res))
    add(IP(src=CLI, dst=SRV) / TCP(sport=sp, dport=80, flags="A", seq=101 + len(req), ack=501 + len(res)))

wrpcap(f"{sys.argv[1]}/expressions.pcap", pkts)
