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
- 56.syn_flood_short_tail.pcap: a real-source flood of 200 SYN/s for 1 s to
  172.31.80.10:80; the client resets every SYN-ACK (RST). Then 1.5 s of
  completed handshakes between two other hosts, and nothing more to port 80.
  Rule 56 must report the flood (a reset handshake is half-open at once).
- 57.syn_flood_crafted_ports.pcap: 300 spoofed SYNs to 192.168.1.10:80 in
  0.6 s. One SYN goes to each of 7 other ports of 192.168.1.10, and 299 SYNs to
  an 8th one, interleaved with the flood. With the unseeded hash
  (MMT_SEC_SYN_FLOOD_HASH_SEED=0), these 8 ports share the home slot of the
  victim, so they fill all its 8 probed slots: rule 57 must still report the
  victim (and the 8th port).
"""
import os
import random
import struct
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


def short_flood_tail():
    server, client = "172.31.80.10", "172.31.80.20"
    pkts = []
    for i in range(200):
        t = T0 + i * 0.005
        sport = random.randrange(1024, 65536)
        seq_cli = random.getrandbits(32)
        syn_synack(pkts, t, client, sport, server, seq_cli)
        pkts.append(pkt(t + 0.0002, client, server, sport, 80, "R", seq_cli + 1))
    # unrelated traffic: completed handshakes between two other hosts, every 20 ms for 1.5 s
    for k in range(75):
        t = T0 + 1.05 + k * 0.02
        sport, seq_cli, seq_srv = 20000 + k, random.getrandbits(32), random.getrandbits(32)
        pkts.append(pkt(t, "10.5.5.5", "10.6.6.6", sport, 443, "S", seq_cli))
        pkts.append(pkt(t + 0.001, "10.6.6.6", "10.5.5.5", 443, sport, "SA", seq_srv, seq_cli + 1, to_server=False))
        pkts.append(pkt(t + 0.002, "10.5.5.5", "10.6.6.6", sport, 443, "A", seq_cli + 1, seq_srv + 1))
    pkts.sort(key=lambda p: p.time)
    return pkts


def mix32(h):
    """murmur3 finalizer, as em_syn_flood_mix() of rule 57"""
    m = 0xffffffff
    h ^= h >> 16
    h = (h * 0x85ebca6b) & m
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & m
    h ^= h >> 16
    return h


def home57(ip, port, seed=0):
    """home slot of ip:port in rule 57's table (4096 slots); the rule copies the network-order address
    into a uint32_t, read here as little-endian (x86_64, aarch64)"""
    v = struct.unpack("<I", bytes(int(b) for b in ip.split(".")))[0]
    return mix32(mix32(v ^ seed) ^ port) % 4096


def crafted_ports():
    victim = "192.168.1.10"
    home = home57(victim, 80)
    decoys = [p for p in range(1, 65536) if p != 80 and home57(victim, p) == home][:8]
    pkts = []

    def syn(t, dport):
        pkts.append(pkt(T0 + t, spoofed_ip(), victim, random.randrange(1024, 65536), dport, "S",
                        random.getrandbits(32)))
    syn(0.0, 80)
    for k, port in enumerate(decoys[:7]):
        syn(0.0001 * (k + 1), port)
    for i in range(1, 300):
        syn(i * 0.002, 80)
        syn(i * 0.002 + 0.001, decoys[7])
    return pkts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    for name, gen in (("57.syn_flood_lan_decoys", lan_decoys),
                      ("56.57.syn_flood_fast", fast_flood),
                      ("56.syn_flood_rst_ack", rst_ack_clients),
                      ("56.syn_flood_short_tail", short_flood_tail),
                      ("57.syn_flood_crafted_ports", crafted_ports)):
        random.seed(name)
        path = os.path.join(out, name + ".pcap")
        wrpcap(path, gen())
        print(path, os.path.getsize(path))


if __name__ == "__main__":
    main()
