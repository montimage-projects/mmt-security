"""Tiny helpers to write deterministic TCP conversations to a pcap with scapy."""
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


class Capture:
    def __init__(self, t0=1700000000.0):
        self.pkts = []
        self.t = t0

    def _add(self, p, dt=0.001):
        self.t += dt
        p.time = self.t
        self.pkts.append(p)

    def session(self, cli, srv, sport, dport, exchanges, mss=None):
        """exchanges: list of (direction, bytes) with direction 'c' (client->server)
        or 's' (server->client). A payload larger than `mss` is split into
        several segments."""
        cseq, sseq = 1000, 5000
        e_c = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        e_s = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        ip_c = IP(src=cli, dst=srv, ttl=64)
        ip_s = IP(src=srv, dst=cli, ttl=64)
        self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="S", seq=cseq - 1))
        self._add(e_s / ip_s / TCP(sport=dport, dport=sport, flags="SA", seq=sseq - 1, ack=cseq))
        self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        last_c = None
        for d, data in exchanges:
            if d == "cr":  # retransmit the last client segment
                ch, seq = last_c
                self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=sseq) / Raw(ch))
                continue
            chunks = [data]
            if mss:
                chunks = [data[i:i + mss] for i in range(0, len(data), mss)]
            for ch in chunks:
                if d == "c":
                    last_c = (ch, cseq)
                    self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(ch))
                    cseq += len(ch)
                    self._add(e_s / ip_s / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq))
                else:
                    self._add(e_s / ip_s / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(ch))
                    sseq += len(ch)
                    self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
        self._add(e_s / ip_s / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
        self._add(e_c / ip_c / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        self.t += 0.1

    def write(self, path):
        wrpcap(path, self.pkts)
