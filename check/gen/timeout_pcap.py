#!/usr/bin/env python3
"""Generate check/timeout/timeout.pcap, the capture of check/check-timeout.sh.

Usage: python3 check/gen/timeout_pcap.py OUTPUT_DIR   (needs scapy)

The output is deterministic (fixed timestamps). From 10.0.0.1 to 10.0.0.2,
UDP datagrams only (the test rules match on udp.dest_port):

- t=0.0    port 2000: event a of rule 9101 (a NOT b within 1 s). The instance
           waits for b; its deadline is t=1.0.
- t=0.5    port 3000: unrelated traffic. The per-message timeout walk runs
           but the deadline has not passed: no verdict.
- t=2.5    port 3000: unrelated traffic. The deadline has passed: the
           timeout transition fires and rule 9101 reports, carried by
           event_0 on a packet that matches none of its events.
- t=5.0    port 2000: event a again (new instance of 9101).
- t=5.5    port 2001: b, in time (< 1 s): the instance fails silently.
- t=8.0    port 3000: unrelated traffic; nothing to report.
- t=10.0   port 2100: event a of rule 9102 (a THEN b within 1 s).
- t=10.5   port 2101: b in time: rule 9102 reports on this packet.
- t=15.0   port 2100: event a of 9102 again.
- t=15.5   port 3000: unrelated traffic.
- t=16.5   port 2101: b, but too late (> 1 s): the instance timed out, no alert.

Expected: one alert of rule 9101 whose event_0 is the t=2.5 timeout message
(about 2.5 s after event_1), and one alert of rule 9102 at t=10.5.
"""
import sys
from scapy.all import Ether, IP, UDP, Raw, wrpcap

T0 = 1795200000.0
CLI, SRV = "10.0.0.1", "10.0.0.2"
pkts = []


def add(t, dport):
    q = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    q /= IP(src=CLI, dst=SRV) / UDP(sport=1000, dport=dport) / Raw(b"x" * 8)
    q.time = T0 + t
    pkts.append(q)


for t, dport in (
    (0.0, 2000), (0.5, 3000), (2.5, 3000), (5.0, 2000), (5.5, 2001),
    (8.0, 3000), (10.0, 2100), (10.5, 2101), (15.0, 2100), (15.5, 3000),
    (16.5, 2101),
):
    add(t, dport)

wrpcap(f"{sys.argv[1]}/timeout.pcap", pkts)
