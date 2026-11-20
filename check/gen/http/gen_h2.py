"""Crafted cleartext HTTP/2 (h2c, prior knowledge) traces for rules 97 and 98.

Usage: python3 gen_h2.py OUTDIR
HPACK is encoded by hand (RFC 7541), without Huffman coding.
"""
import random
import struct
import sys
from tcplib import Capture

out = sys.argv[1]
CLI, SRV = "10.0.0.1", "10.0.0.2"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload


def hint(v, prefix, first=0):
    m = (1 << prefix) - 1
    if v < m:
        return bytes([first | v])
    b = [first | m]
    v -= m
    while v >= 128:
        b.append((v & 127) | 128)
        v >>= 7
    b.append(v)
    return bytes(b)


def hstr(s):
    if isinstance(s, str):
        s = s.encode()
    return hint(len(s), 7) + s


def idx(i):                       # indexed header field
    return hint(i, 7, 0x80)


def lit_inc(name, value):         # literal with incremental indexing
    if isinstance(name, int):
        return hint(name, 6, 0x40) + hstr(value)
    return b"\x40" + hstr(name) + hstr(value)


def lit_noidx(name, value):       # literal without indexing
    if isinstance(name, int):
        return hint(name, 4, 0x00) + hstr(value)
    return b"\x00" + hstr(name) + hstr(value)


SETTINGS = frame(4, 0, 0, struct.pack(">HI", 3, 100) + struct.pack(">HI", 4, 65535))
SETTINGS_ACK = frame(4, 1, 0, b"")
WINUPD = frame(8, 0, 0, struct.pack(">I", 1 << 20))


class H2Conn:
    """One h2c connection: a list of (direction, bytes) segments."""

    def __init__(self):
        self.ex = [("c", PREFACE + SETTINGS + WINUPD), ("s", SETTINGS + SETTINGS_ACK), ("c", SETTINGS_ACK)]
        self.sid = 1

    def request(self, block, body=None, same_segment=True, response=True):
        sid = self.sid
        self.sid += 2
        hdr = frame(1, 0x4 | (0 if body is not None else 0x1), sid, block)
        if body is None:
            self.ex.append(("c", hdr))
        else:
            data = frame(0, 0x1, sid, body)
            if same_segment:
                self.ex.append(("c", hdr + data))
            else:
                self.ex.append(("c", hdr))
                self.ex.append(("c", data))
        if response:
            rb = b'{"status":"ok"}'
            rblock = idx(8) + lit_noidx(31, "application/json")
            self.ex.append(("s", frame(1, 0x4, sid, rblock) + frame(0, 0x1, sid, rb)))


def api_block(first, path, method=3, length=None):
    """A typical client header block. The first request inserts :path,
    :authority, user-agent, content-type in the dynamic table."""
    b = idx(method) + idx(6)
    if first:
        b += lit_inc(4, path) + lit_inc(1, "nrf.5gc.lab:8080") + lit_inc(58, "Open5GS-nf/2.7") + \
            lit_inc(31, "application/json") + lit_inc(19, "application/json")
    else:
        # dynamic table: 62 accept, 63 content-type, 64 user-agent, 65 authority, 66 path
        b += lit_noidx(4, path) + idx(65) + idx(64) + idx(63) + idx(62)
    if length is not None:
        b += lit_noidx(28, str(length))
    return b


def benign_api(c, port, n=12, same=True):
    h = H2Conn()
    bodies = [
        b'{"nfInstanceId":"5f8a2c1e-7b3d-4e9a-a1c2-3d4e5f6a7b8c","nfType":"AMF","nfStatus":"REGISTERED"}',
        b'{"supi":"imsi-208930000000001","servingNetworkName":"5G:mnc093.mcc208.3gppnetwork.org"}',
        b'{"color":"#ff0000","theme":"dark"}',
        b'{"path":"C:\\\\Users\\\\bob\\\\Documents","share":"\\\\\\\\fs01\\\\home"}',
        b'{"discount":"10%","price":"$5","note":"50% off, 100% sure"}',
        b'{"url":"https://example.org/a%20b?x=1#frag","tag":"#release"}',
        b'{"template":"Hello ${name}","msg":"cost: $12.50 (#3)"}',
        b'{"list":[1,2,3],"nested":{"a":null,"b":true,"c":-1.5e3},"s":"tab\\tnew\\nline \\u00e9"}',
    ]
    for i in range(n):
        body = bodies[i % len(bodies)]
        h.request(api_block(i == 0, "/nnrf-nfm/v1/nf-instances/%d" % i, 3, len(body)), body, same_segment=same)
    for i in range(4):
        h.request(api_block(False, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&i=%d" % i, 2))
    c.session(CLI, SRV, port, 8080, h.ex)


# ---------------------------------------------------------------- 97: HPACK bomb
c = Capture(1700010000.0)
# benign API traffic, including a request with many small headers
benign_api(c, 45000)
h = H2Conn()
many = idx(3) + idx(6) + lit_inc(4, "/upload") + lit_inc(1, "lab.example")
for i in range(60):
    many += lit_noidx("x-trace-%02d" % i, "v%02d" % i)
h.request(many, b'{"ok":1}')
c.session(CLI, SRV, 45001, 8080, h.ex)
# benign: one large literal header (a big cookie): large block, no compression
h = H2Conn()
h.request(idx(3) + idx(6) + lit_inc(4, "/login") + lit_inc(1, "lab.example") + lit_noidx(32, "s=" + "a" * 1800), b'{"u":"x"}')
c.session(CLI, SRV, 45002, 8080, h.ex)
# attack: HPACK bomb (CVE-2016-6581): 1 priming block inserts a 3000-byte header,
# then 50 blocks of ~205 bytes reference it 200 times each
h = H2Conn()
prime = idx(3) + idx(6) + lit_inc(4, "/bomb") + lit_inc(1, "lab.example") + lit_inc("x-bomb", "A" * 3000)
h.request(prime, b"{}", response=False)
h.ex.append(("cr", None))  # retransmission of the last priming segment: must not be read twice
# dynamic table: 62 x-bomb, 63 :authority, 64 :path
for i in range(50):
    h.request(idx(3) + idx(6) + idx(64) + idx(63) + idx(62) * 200, b"{}", response=False)
    if i == 0:
        h.ex.append(("cr", None))  # retransmitted bomb block: no second alert
c.session(CLI, SRV, 45003, 8080, h.ex, mss=1448)
c.write(out + "/97.http2_hpack_bomb.pcap")

# ---------------------------------------------------------------- 98: fuzzed JSON bodies
c = Capture(1700020000.0)
benign_api(c, 46000)
benign_api(c, 46001, n=8, same=False)
h = H2Conn()
fuzz = [
    b'{"name":"%n%s%n%s%n%s"}',                                   # format string
    b'{"cmd":"$(id)","ue":"imsi-208930000000001"}',               # command substitution
    b'{"file":"..\\\\..\\\\..\\\\windows\\\\win.ini"}',           # path traversal (JSON-escaped backslashes)
    b'{"supi":"imsi-2089300%00000001"}',                          # URL-encoded NUL
    b'{"nfType":"AMF","x":"`reboot`"}',                           # backticks
    b'{"a":"\\u0000"}',                                           # JSON-escaped NUL
]
# 5Greplay HTTP2_PAYLOAD_FUZZ: the second half of the body replaced by random characters
random.seed(7)
chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;'///:,.<>/?\\"
for base in (b'{"nfInstanceId":"5f8a2c1e-7b3d-4e9a-a1c2-3d4e5f6a7b8c","nfType":"AMF","nfStatus":"REGISTERED"}',
             b'{"supi":"imsi-208930000000001","servingNetworkName":"5G:mnc093.mcc208.3gppnetwork.org"}'):
    b = bytearray(base)
    for i in range(len(b) - 1, len(b) // 2, -1):
        b[i] = chars[random.randrange(len(chars))]
    fuzz.append(bytes(b))
for i, body in enumerate(fuzz):
    h.request(api_block(i == 0, "/nausf-auth/v1/ue-authentications", 3, len(body)), body)
c.session(CLI, SRV, 46002, 8080, h.ex)
c.write(out + "/98.http2_fuzzing.pcap")
print("ok")
