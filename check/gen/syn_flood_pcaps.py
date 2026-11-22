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
- 56.crafted_servers_control.pcap: a real-source flood of 60 SYN/s for 3 s
  (below rule 57's threshold) to 172.31.77.10:80, from t=1.2 s; the client
  resets every SYN-ACK. Completed handshakes between two other hosts every
  50 ms for 5 s. Rule 56 must report the victim 3 times (1/s).
- 56.crafted_servers_attack.pcap: the same flood, plus an attack on rule 56's
  server table with servers crafted for the unseeded hash (seed 0) to share the
  victim's 8 probed slots: 8 of them get 3 spoofed SYN-ACKs each at t=0 (their
  alerts then wait; nothing is sent to them), and after each half-open
  handshake of the victim, a new one sends a SYN-ACK that its client resets.
  With the unseeded hash, each new server used to evict the victim, which never
  reached 3 half-open handshakes; now the pending alerts of the crafted
  servers expire 2 s after they are raised, their slots become evictable, and
  the victim is reported (check-syn-flood-rules.sh verifies this with
  MMT_SEC_SYN_FLOOD_HASH_SEED=0). With any other seed
  (check/pcap/56.crafted_servers_attack.env), rule 56 must report the victim 3
  times, as in the control.
- 57.syn_flood_flush_lowcount.pcap: 120 SYN/s for 1 s to 192.168.1.10:80, and
  destinations crafted for the unseeded hash to share its 8 probed slots, one
  SYN each: 8 in the first 8 ms, then one between two SYNs of the victim. Run
  with MMT_SEC_SYN_FLOOD_HASH_SEED=0 (check/pcap/57.syn_flood_flush_lowcount.env):
  all the slots then have 1 SYN, and on such a tie a new destination must take
  the slot whose window started last (the previous new destination), not the
  victim's: rule 57 must report the victim once.
- 56.57.syn_flood_spoofed_short.pcap: a spoofed flood of 60 SYN in 0.8 s to
  172.31.77.10:80 (below rule 57's threshold), with the server's SYN-ACK
  retransmissions 1 s and 3 s later, then 4 s of completed handshakes between
  two other hosts, and no packet to port 80. It documents a gap: no alert of
  rule 56 (it reports on a packet to the server port) nor of rule 57.
- 56.evict_post_expiry.pcap: the drop of a pending alert that expired. 3
  spoofed SYN-ACKs of 172.31.99.10:80 raise a pending alert at ~1 s; its port
  then stays quiet. 7 other servers crafted for the unseeded hash (seed 0)
  fill the victim's slot run at ~1.5 s, and an 8th one's handshake creates
  its slot at ~5 s: the victim's alert, raised more than 2 s earlier
  (EM_SYN56_EXPIRE_US), is evictable, it has the oldest half-open handshake,
  so the new server takes its slot and drops the pending alert. A witness
  server goes through the same pending-alert path but is then reported by a
  packet to its port, and a probe packet finally reaches the victim's port:
  it would report the victim's alert had it survived. Expected: exactly 1
  alert of rule 56, for the witness. With a larger EM_SYN56_EXPIRE_US the
  victim's slot is still protected when the attacker's slot is created and
  the probe reports the victim: 2 alerts.
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


def ip_le(ip):
    """the network-order address as the rules read it into a uint32_t (little-endian: x86_64, aarch64)"""
    return struct.unpack("<I", bytes(int(b) for b in ip.split(".")))[0]


def home56(ip, port, seed=0):
    """home slot of server ip:port in rule 56's server table (4096 slots), as em_syn56_server()"""
    return mix32(mix32(ip_le(ip) ^ seed) ^ port) % 4096


def ip_str(v):
    return "%d.%d.%d.%d" % (v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255)


def other_traffic(pkts, t0, duration, step):
    """completed handshakes between two other hosts, every step s for duration s"""
    for k in range(int(round(duration / step))):
        t = t0 + k * step
        sport, seq_cli, seq_srv = 20000 + k, random.getrandbits(32), random.getrandbits(32)
        pkts.append(pkt(t, "10.5.5.5", "10.6.6.6", sport, 443, "S", seq_cli))
        pkts.append(pkt(t + 0.001, "10.6.6.6", "10.5.5.5", 443, sport, "SA", seq_srv, seq_cli + 1, to_server=False))
        pkts.append(pkt(t + 0.002, "10.5.5.5", "10.6.6.6", sport, 443, "A", seq_cli + 1, seq_srv + 1))


def crafted_servers(attack):
    victim, client = "172.31.77.10", "172.31.77.20"
    home = home56(victim, 80)
    servers, x = [], 1
    while len(servers) < 8 + 180:
        ip = ip_str(0x0A000000 + x)
        x += 1
        if home56(ip, 80) == home:
            servers.append(ip)
    pkts = []
    if attack:
        # 8 crafted servers, 3 half-open handshakes each (SYN-ACKs that no client answers)
        for k in range(8):
            for i in range(3):
                pkts.append(pkt(T0 + k * 0.001 + i * 0.0001, servers[k], ip_str(0x0B000000 + k * 8 + i), 80, 2000 + i,
                                "SA", random.getrandbits(32), random.getrandbits(32), to_server=False))
    for i in range(180):
        t = T0 + 1.2 + i / 60
        sport, seq_cli = 10000 + i, random.getrandbits(32)
        syn_synack(pkts, t, client, sport, victim, seq_cli)
        pkts.append(pkt(t + 0.0002, client, victim, sport, 80, "R", seq_cli + 1))
        if attack:
            # a new crafted server: a SYN-ACK, reset by its client (half-open at once)
            srv, cli, seq_srv = servers[8 + i], ip_str(0x0C000000 + i), random.getrandbits(32)
            pkts.append(pkt(t + 0.0003, srv, cli, 80, 3000, "SA", seq_srv, random.getrandbits(32), to_server=False))
            pkts.append(pkt(t + 0.0004, cli, srv, 3000, 80, "R", random.getrandbits(32)))
    other_traffic(pkts, T0, 5.0, 0.05)
    pkts.sort(key=lambda p: p.time)
    return pkts


def crafted_servers_control():
    return crafted_servers(False)


def crafted_servers_attack():
    return crafted_servers(True)


def flush_lowcount():
    victim = "192.168.1.10"
    home = home57(victim, 80)
    keys, x = [], 1
    while len(keys) < 8 + 119:
        ip = ip_str(0xC0A80000 + (x >> 4))
        port = 1024 + (x & 15) * 4000
        x += 1
        if (ip, port) != (victim, 80) and home57(ip, port) == home:
            keys.append((ip, port))
    pkts = []

    def syn(t, dst, dport):
        pkts.append(pkt(T0 + t, spoofed_ip(), dst, random.randrange(1024, 65536), dport, "S", random.getrandbits(32)))
    syn(0.0, victim, 80)
    for j in range(8):
        syn(0.0005 + j * 0.001, *keys[j])
    for i in range(1, 120):
        syn(i / 120, victim, 80)
        syn(i / 120 + 1 / 240, *keys[7 + i])
    pkts.sort(key=lambda p: p.time)
    return pkts


def spoofed_short():
    victim = "172.31.77.10"
    pkts = []
    for i in range(60):
        t = T0 + i * 0.8 / 60
        client, sport, seq_cli, seq_srv = ip_str(0x0D000000 + i), 30000 + i, random.getrandbits(32), random.getrandbits(32)
        pkts.append(pkt(t, client, victim, sport, 80, "S", seq_cli))
        for dt in (0.0001, 1.0, 3.0):
            pkts.append(pkt(t + dt, victim, client, 80, sport, "SA", seq_srv, seq_cli + 1, to_server=False))
    other_traffic(pkts, T0 + 0.9, 4.0, 0.02)
    pkts.sort(key=lambda p: p.time)
    return pkts


def evict_post_expiry():
    victim, witness = "172.31.99.10", "172.31.99.20"
    home = home56(victim, 80)
    others, x = [], 1
    while len(others) < 8:
        ip = ip_str(0x0A000000 + x)
        x += 1
        if home56(ip, 80) == home:
            others.append(ip)
    fillers, attacker = others[:7], others[7]
    pkts = []
    # the victim's 3 half-open handshakes: spoofed SYN-ACKs (nothing is ever
    # sent to its port, so the alert they raise stays pending)
    for i in range(3):
        pkts.append(pkt(T0 + i * 0.001, victim, ip_str(0x0B000000 + i), 80, 4000 + i, "SA",
                        random.getrandbits(32), random.getrandbits(32), to_server=False))
    # 7 crafted servers fill the victim's slot run, one half-open handshake each
    for k, ip in enumerate(fillers):
        pkts.append(pkt(T0 + 0.5 + k * 0.001, ip, ip_str(0x0C000000 + k), 80, 5000 + k, "SA",
                        random.getrandbits(32), random.getrandbits(32), to_server=False))
    # the attacker joins the slot run: its handshake leaves the FIFO at ~5 s,
    # when the victim's alert (raised at ~1 s) expired and is dropped
    pkts.append(pkt(T0 + 4.0, attacker, ip_str(0x0D000000), 80, 6000, "SA",
                    random.getrandbits(32), random.getrandbits(32), to_server=False))
    # the witness goes through the same pending-alert path; the packet to its
    # port both pops its handshakes and reports the alert
    for i in range(3):
        pkts.append(pkt(T0 + 5.0 + i * 0.001, witness, ip_str(0x0E000000 + i), 80, 7000 + i, "SA",
                        random.getrandbits(32), random.getrandbits(32), to_server=False))
    pkts.append(pkt(T0 + 6.5, "10.20.30.40", witness, 41000, 80, "S", random.getrandbits(32)))
    # probe: would report the victim's alert if the eviction had not dropped it
    pkts.append(pkt(T0 + 7.0, "10.20.30.41", victim, 41001, 80, "S", random.getrandbits(32)))
    other_traffic(pkts, T0, 8.0, 0.05)
    pkts.sort(key=lambda p: p.time)
    return pkts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    for name, gen in (("57.syn_flood_lan_decoys", lan_decoys),
                      ("56.57.syn_flood_fast", fast_flood),
                      ("56.syn_flood_rst_ack", rst_ack_clients),
                      ("56.syn_flood_short_tail", short_flood_tail),
                      ("57.syn_flood_crafted_ports", crafted_ports),
                      ("56.crafted_servers_control", crafted_servers_control),
                      ("56.crafted_servers_attack", crafted_servers_attack),
                      ("57.syn_flood_flush_lowcount", flush_lowcount),
                      ("56.57.syn_flood_spoofed_short", spoofed_short),
                      ("56.evict_post_expiry", evict_post_expiry)):
        random.seed(name)
        path = os.path.join(out, name + ".pcap")
        wrpcap(path, gen())
        print(path, os.path.getsize(path))


if __name__ == "__main__":
    main()
