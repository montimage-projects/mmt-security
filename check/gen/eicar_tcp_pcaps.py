#!/usr/bin/env python3
"""Generate the extra check pcap of rule 67 (EICAR in a TCP stream, -R).

Usage: python3 check/gen/eicar_tcp_pcaps.py OUTPUT_DIR   (needs scapy)

The output is deterministic (fixed seed and timestamps).

- 67.EICAR_TCP_two_uploads.pcap: one HTTP flow, 10.0.0.1:5000 -> 10.0.0.2:80,
  uploads the EICAR test file twice. Each file goes over two TCP segments:
  the test string completes on the second segment of each upload. Rule 67
  must report the flow twice (once per occurrence), and only twice: the
  pure ACK, response and FIN packets of the flow, which re-present the same
  reassembled image, must not alert again (fork issue #22).
"""
import sys
from scapy.all import Ether, IP, TCP, Raw, wrpcap

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

C, S, DPORT = "10.0.0.1", "10.0.0.2", 80
TS = 1700000200.0          # fixed epoch base; +0.005 s per packet


def pkt(src, dst, sport, dport, flags, seq, ack, payload=b""):
    p = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
         / IP(src=src, dst=dst)
         / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack))
    if payload:
        p = p / Raw(load=payload)
    return p


def client(flags, seq, ack=0, payload=b""):
    return pkt(C, S, 5000, DPORT, flags, seq, ack, payload)


def server(flags, seq, ack=0, payload=b""):
    return pkt(S, C, DPORT, 5000, flags, seq, ack, payload)


def main(out_dir):
    c_seq, s_seq = 1000, 2000
    req = lambda path: (b"POST /%s HTTP/1.1\r\nHost: x\r\n"
                        b"Content-Length: 68\r\n\r\n" % path)

    pkts = [
        client("S",  c_seq),                  # 1  SYN
        server("SA", s_seq, c_seq + 1),       # 2  SYN-ACK
        client("A",  c_seq + 1, s_seq + 1),   # 3  ACK
    ]
    # upload 1: header + first 40 bytes of the file, then the 28 last ones;
    # the test string completes on packet 5 -> first alert
    d1 = req(b"a") + EICAR[:40]
    pkts += [
        client("PA", c_seq + 1, s_seq + 1, d1),                       # 4
        server("A", s_seq + 1, c_seq + 1 + len(d1)),                  # 5
        client("PA", c_seq + 1 + len(d1), s_seq + 1, EICAR[40:]),     # 6 -> alert 1
        server("PA", s_seq + 1, c_seq + 1 + len(d1) + 28,
               b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),      # 7
        client("A", c_seq + 1 + len(d1) + 28, s_seq + 39),            # 8
    ]
    # upload 2: header + first 20 bytes, then the 48 last ones;
    # the test string completes on packet 11 -> second alert
    c2 = c_seq + 1 + len(d1) + 28
    d2 = req(b"b") + EICAR[:20]
    pkts += [
        client("PA", c2, s_seq + 39, d2),                             # 9
        server("A", s_seq + 39, c2 + len(d2)),                        # 10
        client("PA", c2 + len(d2), s_seq + 39, EICAR[20:]),           # 11 -> alert 2
        server("A", s_seq + 39, c2 + len(d2) + 48),                   # 12
        client("FA", c2 + len(d2) + 48, s_seq + 39),                  # 13 FIN
        server("FA", s_seq + 39, c2 + len(d2) + 49),                  # 14 FIN
        client("A", c2 + len(d2) + 49, s_seq + 40),                   # 15
    ]
    for i, p in enumerate(pkts):
        p.time = TS + i * 0.005
    wrpcap("%s/67.EICAR_TCP_two_uploads.pcap" % out_dir, pkts)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "check/pcap")
