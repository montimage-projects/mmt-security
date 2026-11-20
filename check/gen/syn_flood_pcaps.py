#!/usr/bin/env python3
"""Generate the SYN flood check pcaps of rules 56 and 57.

Usage: python3 check/gen/syn_flood_pcaps.py OUTPUT_DIR   (needs scapy)

The output is deterministic (fixed seed and timestamps). Each pcap is kept
under 100 KB, so the packets are minimal Ethernet + IPv4 + TCP headers.

- 57.syn_flood_lan_decoys.pcap: 300 spoofed SYNs to 192.168.1.10:80 in 0.6 s,
  each one followed by a SYN to one of 12 other hosts of 192.168.2.0/24 on
  port 80 (25 SYNs each). Rule 57 must report the victim once, and no decoy.
- 56.57.syn_flood_fast.pcap: a 2000 SYN/s flood from spoofed sources for 0.3 s
  (600 SYNs, each answered by a SYN-ACK), then the flood tails off: 10 more
  SYNs between 1.3 s and 1.5 s. No handshake completes.
- 56.syn_flood_rst_ack.pcap: one real client sends 60 SYNs at 200/s; it answers
  every SYN-ACK with RST|ACK (flags 0x14), which does not complete the
  handshake. 5 more SYNs 1.3 s later.
"""
import os
import random
import sys

from scapy.all import Ether, IP, TCP, wrpcap

T0 = 1795190000.0
SRV_MAC = "02:00:00:00:00:10"
CLI_MAC = "02:00:00:00:00:20"


def pkt(t, src, dst, sport, dport, flags, seq=0, ack=0, to_server=True):
    p = (Ether(src=CLI_MAC if to_server else SRV_MAC, dst=SRV_MAC if to_server else CLI_MAC)
         / IP(src=src, dst=dst, ttl=64, id=random.randrange(65536))
         / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240))
    p.time = round(t, 6)
    return p


def spoofed_ip():
    return "10.%d.%d.%d" % (random.randrange(256), random.randrange(256), random.randrange(1, 255))


def lan_decoys():
    victim = "192.168.1.10"
    decoys = ["192.168.2.%d" % (11 + i) for i in range(12)]
    pkts = []
    for i in range(300):
        t = T0 + i * 0.002
        pkts.append(pkt(t, spoofed_ip(), victim, random.randrange(1024, 65536), 80, "S", random.getrandbits(32)))
        pkts.append(pkt(t + 0.001, spoofed_ip(), decoys[i % 12], random.randrange(1024, 65536), 80, "S",
                        random.getrandbits(32)))
    return pkts


def syn_synack(pkts, t, src, sport, server, seq_cli):
    seq_srv = random.getrandbits(32)
    pkts.append(pkt(t, src, server, sport, 80, "S", seq_cli))
    pkts.append(pkt(t + 0.0001, server, src, 80, sport, "SA", seq_srv, seq_cli + 1, to_server=False))
    return seq_srv


def fast_flood():
    server = "172.31.78.10"
    pkts = []
    for i in range(600):
        syn_synack(pkts, T0 + i * 0.0005, spoofed_ip(), random.randrange(1024, 65536), server, random.getrandbits(32))
    for i in range(10):
        syn_synack(pkts, T0 + 1.3 + i * 0.02, spoofed_ip(), random.randrange(1024, 65536), server,
                   random.getrandbits(32))
    return pkts


def rst_ack_clients():
    server, client = "172.31.79.10", "172.31.79.20"
    pkts = []
    times = [T0 + i * 0.005 for i in range(60)] + [T0 + 1.3 + i * 0.02 for i in range(5)]
    for t in times:
        sport = random.randrange(1024, 65536)
        seq_cli = random.getrandbits(32)
        seq_srv = syn_synack(pkts, t, client, sport, server, seq_cli)
        # RST|ACK: the ACK flag is set, but a reset does not complete the handshake
        pkts.append(pkt(t + 0.0002, client, server, sport, 80, "RA", seq_cli + 1, seq_srv + 1))
    return pkts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    for name, gen in (("57.syn_flood_lan_decoys", lan_decoys),
                      ("56.57.syn_flood_fast", fast_flood),
                      ("56.syn_flood_rst_ack", rst_ack_clients)):
        random.seed(name)
        path = os.path.join(out, name + ".pcap")
        wrpcap(path, gen())
        print(path, os.path.getsize(path))


if __name__ == "__main__":
    main()
