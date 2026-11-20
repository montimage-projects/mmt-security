#!/usr/bin/env python3
"""
Craft the DICOM check captures for rules 200-228 (Montimage/mmt-security
#24, #33, #34, #44).

  dicom_pcaps.py attacks <out.pcap>
      one TCP connection per attack, sent to the lab SCP 10.77.0.10:11112
  dicom_pcaps.py merge <benign.pcap> <attacks.pcap> <out.pcap>
      the attacks, shifted to start 2 s after the benign capture ends
  dicom_pcaps.py flood <out.pcap>
      rule 220: 21 associations spread over 10 s (benign), then 8
      associations, a 6 s pause and 30 A-ASSOCIATE-RQ within 0.1 s (attack)

  dicom_pcaps.py segmenting-benign <out.pcap>
      the PDU boundary tracker (rules 200-228, Montimage/mmt-security#44): benign
      C-STOREs segmented as a TCP stack does, with PDU headers split across
      segments and pixel data that reads as PDU headers at segment starts; no
      rule of the batch may alert
  dicom_pcaps.py segmenting-attacks <out.pcap>
      attacks after such data in the same connection, which the tracker must
      still see; a retransmitted attack; 12 parallel associations from one client
  dicom_pcaps.py rates <out.pcap>
      the sliding windows and per-pair keys of rules 220, 223 and 228
  dicom_pcaps.py parallel-sources <out.pcap>
      rules 220 and 223: 10 sources of one /16 at once, each over the threshold

Except in the segmenting captures, every PDU is sent in one TCP segment that
starts with its PDU header, which is what mmt-dpi needs to extract dicom.*
attributes.
"""
import struct
import sys

from scapy.all import IP, TCP, Ether, PcapReader, wrpcap

SERVER = "10.77.0.10"
PORT = 11112
VERIFICATION = b"1.2.840.10008.1.1"
FIND_PATIENT = b"1.2.840.10008.5.1.4.1.2.1.1"
CT_STORAGE = b"1.2.840.10008.5.1.4.1.1.2"
IMPLICIT_LE = b"1.2.840.10008.1.2"
EXPLICIT_LE = b"1.2.840.10008.1.2.1"
APP_CTX = b"1.2.840.10008.3.1.1.1"


class Clock:
    def __init__(self, t0):
        self.t = t0

    def tick(self, dt=0.0005):
        self.t += dt
        return self.t


class Conn:
    """One TCP connection; packets are appended to a shared list."""

    def __init__(self, out, clock, cip, cport, sip=SERVER, sport=PORT):
        self.out, self.clock = out, clock
        self.c, self.s = (cip, cport), (sip, sport)
        self.seq = {True: 1000, False: 50000}  # next seq, by "from client"
        self.mac = {True: "02:00:00:00:00:01", False: "02:00:00:00:00:02"}

    def _pkt(self, frm_client, flags, payload=b"", dt=0.0005):
        src, dst = (self.c, self.s) if frm_client else (self.s, self.c)
        p = (Ether(src=self.mac[frm_client], dst=self.mac[not frm_client])
             / IP(src=src[0], dst=dst[0])
             / TCP(sport=src[1], dport=dst[1], flags=flags,
                   seq=self.seq[frm_client], ack=self.seq[not frm_client]
                   if "A" in flags else 0, window=65535))
        if payload:
            p = p / payload
        p.time = self.clock.tick(dt)
        self.out.append(p)
        self.seq[frm_client] += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

    def open(self):
        self._pkt(True, "S")
        self._pkt(False, "SA")
        self._pkt(True, "A")
        return self

    def send(self, frm_client, data, dt=0.002):
        for i in range(0, len(data), 1448):
            self._pkt(frm_client, "PA", data[i:i + 1448], dt)
        self._pkt(not frm_client, "A")

    def close(self):
        self._pkt(True, "FA")
        self._pkt(False, "FA")
        self._pkt(True, "A")

    def reset(self):
        self._pkt(True, "RA")


# ---- PDUs (PS3.8 section 9.3) ------------------------------------------------

def ae(title):
    return title.ljust(16)[:16] if isinstance(title, bytes) else title.encode().ljust(16)[:16]


def item(t, val):
    return struct.pack(">BBH", t, 0, len(val)) + val


def pdu(t, body, length=None):
    return struct.pack(">BBI", t, 0, len(body) if length is None else length) + body


def assoc_rq(called, calling, ctxs=((1, VERIFICATION, (IMPLICIT_LE,)),),
             fixed_override=None, length=None, version=1):
    if fixed_override is not None:
        fixed = fixed_override
    else:
        fixed = struct.pack(">HH", version, 0) + ae(called) + ae(calling) + b"\0" * 32
    var = item(0x10, APP_CTX)
    for cid, abstract, tss in ctxs:
        var += item(0x20, bytes([cid, 0, 0, 0]) + item(0x30, abstract)
                    + b"".join(item(0x40, ts) for ts in tss))
    var += item(0x50, item(0x51, struct.pack(">I", 16384))
                + item(0x52, b"1.2.826.0.1.3680043.9.9999"))
    return pdu(1, fixed + var, length)


def assoc_ac(called, calling, ctxs=((1, IMPLICIT_LE),)):
    fixed = struct.pack(">HH", 1, 0) + ae(called) + ae(calling) + b"\0" * 32
    var = item(0x10, APP_CTX)
    for cid, ts in ctxs:
        var += item(0x21, bytes([cid, 0, 0, 0]) + item(0x40, ts))
    var += item(0x50, item(0x51, struct.pack(">I", 16384)))
    return pdu(2, fixed + var)


def pdata(*pdvs):
    """pdvs: (context id, message control header, value)"""
    return pdu(4, b"".join(struct.pack(">IBB", len(v) + 2, c, f) + v for c, f, v in pdvs))


RELEASE_RQ = pdu(5, b"\0" * 4)
RELEASE_RP = pdu(6, b"\0" * 4)

# ---- DIMSE (PS3.7 section E, implicit VR little endian) ----------------------


def even(v, pad=b"\0"):
    return v + pad if len(v) % 2 else v


def el(elem, val, group=0):
    return struct.pack("<HHI", group, elem, len(val)) + val


def us(v):
    return struct.pack("<H", v)


def command(*elements):
    body = b"".join(elements)
    return el(0x0000, struct.pack("<I", len(body))) + body


def echo_rq(msg_id=1):
    return command(el(0x0002, even(VERIFICATION)), el(0x0100, us(0x0030)),
                   el(0x0110, us(msg_id)), el(0x0800, us(0x0101)))


def echo_rsp(msg_id=1, status=0):
    return command(el(0x0002, even(VERIFICATION)), el(0x0100, us(0x8030)),
                   el(0x0120, us(msg_id)), el(0x0800, us(0x0101)), el(0x0900, us(status)))


def find_rq(msg_id):
    return command(el(0x0002, even(FIND_PATIENT)), el(0x0100, us(0x0020)),
                   el(0x0110, us(msg_id)), el(0x0700, us(0)), el(0x0800, us(0x0000)))


def find_rsp(msg_id, status, dataset=False):
    return command(el(0x0002, even(FIND_PATIENT)), el(0x0100, us(0x8020)),
                   el(0x0120, us(msg_id)), el(0x0800, us(0x0000 if dataset else 0x0101)),
                   el(0x0900, us(status)))


def patient_query(name):
    return (el(0x0052, even(b"PATIENT", b" "), group=0x0008)
            + el(0x0010, even(name, b" "), group=0x0010)
            + el(0x0020, b"", group=0x0010))


# ---- sessions ----------------------------------------------------------------


def associate(out, clock, cip, cport, called="LABPACS", calling="LABSCU", ctxs=None):
    c = Conn(out, clock, cip, cport).open()
    c.send(True, assoc_rq(called, calling, ctxs or ((1, VERIFICATION, (IMPLICIT_LE,)),)))
    c.send(False, assoc_ac(called, calling))
    return c


def release(c):
    c.send(True, RELEASE_RQ)
    c.send(False, RELEASE_RP)
    c.close()


def echo(c, msg_id=1):
    c.send(True, pdata((1, 3, echo_rq(msg_id))))
    c.send(False, pdata((1, 3, echo_rsp(msg_id))))


def attacks(out, clock):
    gap = lambda: clock.tick(0.3)  # noqa: E731
    A = "10.66.0.66"  # attacker
    B = "10.77.0.30"  # a second, benign workstation

    # benign: AE titles with '-' and '.', allowed by the AE VR (#34, rule 221)
    c = associate(out, clock, B, 41001, called="ARCHIVE-1.MAIN", calling="CT.SCANNER-2")
    echo(c)
    release(c)
    gap()

    # benign: a C-FIND that the SCU cancels; final status 0xFE00 Cancel and
    # 0xFF01 Pending (warning) (#34 comment, rule 202)
    c = associate(out, clock, B, 41002, ctxs=((1, FIND_PATIENT, (IMPLICIT_LE,)),))
    c.send(True, pdata((1, 3, find_rq(5))))
    c.send(True, pdata((1, 2, patient_query(b"DOE*"))))
    c.send(False, pdata((1, 3, find_rsp(5, 0xFF01, dataset=True))))
    c.send(False, pdata((1, 2, patient_query(b"DOE^JOHN"))))
    c.send(True, pdata((1, 3, command(el(0x0100, us(0x0FFF)), el(0x0120, us(5)),
                                      el(0x0800, us(0x0101))))))
    c.send(False, pdata((1, 3, find_rsp(5, 0xFE00))))
    release(c)
    gap()

    # 202: a response with an error status (0xC000, unable to process)
    c = associate(out, clock, A, 42001)
    c.send(True, pdata((1, 3, echo_rq(1))))
    c.send(False, pdata((1, 3, echo_rsp(1, status=0xC000))))
    release(c)
    gap()

    # 213: a C-ECHO-RQ with the response bit set: command field 0x8030 but
    # Message ID (0000,0110) and no Status, i.e. a request's structure
    c = associate(out, clock, A, 42002)
    c.send(True, pdata((1, 3, command(el(0x0002, even(VERIFICATION)), el(0x0100, us(0x8030)),
                                      el(0x0110, us(1)), el(0x0800, us(0x0101))))))
    c.reset()
    gap()

    # 201: unknown command field 0x1234 in a command PDV
    c = associate(out, clock, A, 42003)
    c.send(True, pdata((1, 3, command(el(0x0002, even(VERIFICATION)), el(0x0100, us(0x1234)),
                                      el(0x0110, us(1)), el(0x0800, us(0x0101))))))
    c.reset()
    gap()

    # 216: a second A-ASSOCIATE-RQ in the same TCP connection after P-DATA
    c = associate(out, clock, A, 42004)
    echo(c)
    c.send(True, assoc_rq("LABPACS", "LABSCU"))
    c.reset()
    gap()

    # 221: Called AE titles from the attacker name list, with a backslash,
    # with a control character
    for port, called in ((42005, b"EVIL_SCP"), (42006, b"AB\\CD"), (42007, b"AB\x01CD")):
        c = Conn(out, clock, A, port).open()
        c.send(True, assoc_rq(called, "ATKSCU"))
        c.reset()
        gap()

    # 223: wildcard enumeration, 12 C-FIND queries A* .. L* within ~1 s
    # (alerts on the 10th, 11th and 12th)
    c = associate(out, clock, A, 42008, ctxs=((1, FIND_PATIENT, (IMPLICIT_LE,)),))
    for i, letter in enumerate(b"ABCDEFGHIJKL"):
        c.send(True, pdata((1, 3, find_rq(i + 1))))
        c.send(True, pdata((1, 2, patient_query(bytes([letter]) + b"*"))), dt=0.04)
        c.send(False, pdata((1, 3, find_rsp(i + 1, 0x0000))))
    release(c)
    gap()

    # 227: A-ASSOCIATE-RQ declaring 40000 bytes (> 32768)
    c = Conn(out, clock, A, 42009).open()
    c.send(True, assoc_rq("LABPACS", "ATKSCU", length=40000))
    c.reset()
    gap()

    # 228: a normal association, then one with the AE titles swapped
    c = associate(out, clock, "10.66.0.68", 42010, called="LABPACS", calling="ATKSCU")
    release(c)
    gap()
    c = Conn(out, clock, "10.66.0.68", 42011).open()
    c.send(True, assoc_rq("ATKSCU", "LABPACS"))
    c.reset()
    gap()

    # 219: a 40-byte Called AE written into the RQ: the bytes past the 16-byte
    # field overrun the Calling AE and the 32-byte reserved field
    fixed = struct.pack(">HH", 1, 0) + b"A" * 40 + ae("ATKSCU") + b"\0" * 8
    c = Conn(out, clock, A, 42012).open()
    c.send(True, assoc_rq(None, None, fixed_override=fixed))
    c.reset()
    gap()

    # 209: an A-ASSOCIATE-RQ with protocol version 2 after a valid association
    c = associate(out, clock, A, 42019)
    c.send(True, assoc_rq("LABPACS", "LABSCU", version=2))
    c.reset()
    gap()

    # malformed PDU headers inside an association (rules 200, 208, 224, 226)
    for port, bad in ((42013, pdu(9, b"\0" * 4)),          # 200: type 9
                      (42014, pdu(4, b"")),                # 208: P-DATA length 0
                      (42015, pdu(5, b"")),                # 208 + 226: A-RELEASE-RQ length 0
                      (42016, pdu(1, b"\0" * 60)),         # 224: A-ASSOCIATE-RQ length 60
                      (42017, pdu(5, b"\0" * 10)),         # 226: A-RELEASE-RQ length 10
                      (42018, pdu(7, b"\0" * 20))):        # 226: A-ABORT length 20
        c = associate(out, clock, A, port)
        echo(c)
        c.send(True, bad)
        c.reset()
        gap()


def flood(out, clock):
    def one(cip, cport, dt):
        c = Conn(out, clock, cip, cport)
        c._pkt(True, "S", dt=dt)
        c._pkt(False, "SA", dt=0.0001)
        c._pkt(True, "A", dt=0.0001)
        c.send(True, assoc_rq("LABPACS", "MODALITY"), dt=0.0001)
        c.send(False, assoc_ac("LABPACS", "MODALITY"), dt=0.0001)
        c.reset()

    # benign: 21 associations from one modality, 2 per second (never more
    # than 11 in any 5 s window)
    for i in range(21):
        one("10.77.0.40", 43000 + i, 0.5)
    clock.tick(10)
    # attack: 8 associations, a 6 s pause, then 30 within 0.1 s
    for i in range(8):
        one("10.66.0.67", 44000 + i, 0.2)
    clock.tick(6)
    for i in range(30):
        one("10.66.0.67", 44100 + i, 0.003)



# ---- PDU boundary tracker, sliding windows (follow-up of fork PR #15) --------

MSS = 1448
MAXPDU = 4096  # the maximum PDU length both peers accept (User Information, 51H)


def store_rq(msg_id):
    return command(el(0x0002, even(CT_STORAGE)), el(0x0100, us(0x0001)),
                   el(0x0110, us(msg_id)), el(0x0700, us(0)), el(0x0800, us(0x0000)),
                   el(0x1000, even(b"1.2.826.0.1.3680043.9.15.%d" % msg_id)))


def store_rsp(msg_id):
    return command(el(0x0002, even(CT_STORAGE)), el(0x0100, us(0x8001)),
                   el(0x0120, us(msg_id)), el(0x0800, us(0x0101)), el(0x0900, us(0)),
                   el(0x1000, even(b"1.2.826.0.1.3680043.9.15.%d" % msg_id)))


def dataset(msg_id, pixels):
    return (el(0x0016, even(CT_STORAGE), group=0x0008)
            + el(0x0018, even(b"1.2.826.0.1.3680043.9.15.%d" % msg_id), group=0x0008)
            + el(0x0010, pixels, group=0x7FE0))


DS_PREFIX = len(dataset(1, b""))  # data set bytes before the pixels


def store_pdus(msg_id, pixels):
    """the P-DATA-TF PDUs of one C-STORE-RQ: the command, then the data set in
    PDUs of at most MAXPDU bytes"""
    ds = dataset(msg_id, pixels)
    frag = MAXPDU - 12
    chunks = [ds[i:i + frag] for i in range(0, len(ds), frag)]
    return [pdata((1, 3, store_rq(msg_id)))] + [
        pdata((1, 2 if k == len(chunks) - 1 else 0, ch)) for k, ch in enumerate(chunks)]


def headers(pdus):
    """offsets of the PDU headers in the concatenation of pdus"""
    out, pos = [], 0
    for p in pdus:
        out.append(pos)
        pos += len(p)
    return out


def cut(length, forced=()):
    """segment boundaries (start, end) of a stream of length bytes: every MSS
    bytes, and at each forced offset (the segmenting restarts there)"""
    forced = sorted(set(f for f in forced if 0 < f < length))
    bounds, pos = [], 0
    while pos < length:
        nxt = min(pos + MSS, length)
        for f in forced:
            if pos < f < nxt:
                nxt = f
                break
        bounds.append((pos, nxt))
        pos = nxt
    return bounds


def send_stream(c, frm_client, data, bounds, drop=(), dup=(), dt=0.0002):
    """send data cut at bounds; the segments whose index is in drop are not
    captured (their sequence space is skipped), those in dup are sent twice"""
    for i, (a, b) in enumerate(bounds):
        if i in drop:
            c.seq[frm_client] += b - a
            continue
        c._pkt(frm_client, "PA", data[a:b], dt)
        if i in dup:
            c.seq[frm_client] -= b - a
            c._pkt(frm_client, "PA", data[a:b], dt)
    c._pkt(not frm_client, "A")


def dcmtk_segments(pdus, split=None, drop=None):
    """DCMTK's segmenting: the 12-byte PDU and PDV header of a P-DATA-TF in a
    segment of its own, then the rest in segments of MSS bytes. split=(k, j):
    the header of PDU k comes in two segments of j and 12 - j bytes.
    drop=(k, i): body segment i of PDU k is not captured. Returns a list of
    (bytes, captured)."""
    out = []
    for k, p in enumerate(pdus):
        if split is not None and split[0] == k:
            out += [(p[:split[1]], True), (p[split[1]:12], True)]
        else:
            out.append((p[:12], True))
        body = p[12:]
        for i in range(0, len(body), MSS):
            out.append((body[i:i + MSS], drop != (k, i // MSS)))
    return out


def send_segments(c, frm_client, segs, dt=0.0002):
    for data, captured in segs:
        if captured:
            c._pkt(frm_client, "PA", data, dt)
        else:
            c.seq[frm_client] += len(data)
    c._pkt(not frm_client, "A")


def dcmtk_body_starts(n_pixels):
    """offsets in the pixel data of the body segments that dcmtk_segments starts"""
    out, frag = [], MAXPDU - 12
    for k in range(0, DS_PREFIX + n_pixels, frag):
        for i in range(0, frag, MSS):
            off = k + i - DS_PREFIX
            if 0 <= off and off + 10 <= n_pixels:
                out.append(off)
    return out


def pixels_101(n):
    """16-bit pixel words 1, 0, 1 repeated: 01 00 00 00 01 00 reads as an
    A-ASSOCIATE-RQ header of length 256 that mmt-dpi accepts"""
    return (struct.pack("<3H", 1, 0, 1) * (n // 6 + 1))[:n]


def pixels_zero(n, runs=()):
    """zero background (00 00 00 00 00 00 reads as a PDU of type 0, length 0),
    with the byte string v at offset off for each (off, v) of runs"""
    b = bytearray(n)
    for off, v in runs:
        b[off:off + len(v)] = v
    return bytes(b)


# data that reads as an A-ASSOCIATE-RQ header with the fixed fields mmt-dpi checks
FAKE_RQ_FIXED = b"\x01\x00\x00\x00\x01\x00\x00\x01\x00\x00"


def fake_rq_full(length=200):
    """data that reads as the start of a whole A-ASSOCIATE-RQ: the fixed fields,
    then the Application Context Item"""
    return (struct.pack(">BBIHH", 1, 0, length, 1, 0) + ae("LABPACS") + ae("LABSCU")
            + b"\0" * 32 + item(0x10, APP_CTX))


def fake_rq(version=1, called="LABPACS", calling="LABSCU", length=256, reserved=b"\0" * 32):
    """data that reads as an A-ASSOCIATE-RQ that mmt-dpi accepts"""
    return struct.pack(">BBIHH", 1, 0, length, version, 0) + ae(called) + ae(calling) + reserved


# data that reads as a PDU header that a rule of the batch flags, if read at a
# segment start inside a PDU: 200 (type 0), 208 (length 0), 209 (version 2), 219
# (reserved bytes), 220 (many A-ASSOCIATE-RQ), 221 (called AE), 224 (A-ASSOCIATE
# of length 32), 226 (A-RELEASE-RQ of length 16), 227 (length 36864), 228 (AE
# titles swapped against the association of the connection)
DATA_HEADERS = [
    fake_rq(version=2, reserved=b"\x55" * 32),
    struct.pack(">BBI", 1, 0, 32),
    fake_rq(called="EVIL_SCP"),
    struct.pack(">BBI", 5, 0, 16),
    fake_rq(length=36864),
    b"\x00" * 6,
    fake_rq(called="LABSCU", calling="LABPACS"),
    b"\x01\x00\x00\x00\x01\x00",
    FAKE_RQ_FIXED,
]


def store_with_straddles(c, msg_id, pixels, splits):
    """one C-STORE-RQ in MSS segments (pynetdicom: one write per PDU, coalesced),
    with the header of PDU k split j + (6 - j) for each (k, j) of splits"""
    pdus = store_pdus(msg_id, pixels)
    data = b"".join(pdus)
    hs = headers(pdus)
    assert len(pdus) > max(k for k, _ in splits)
    send_stream(c, True, data, cut(len(data), [hs[k] + j for k, j in splits]))
    c.send(False, pdata((1, 3, store_rsp(msg_id))))


def store_lost_header(c, msg_id):
    """one C-STORE-RQ of zero pixels in MSS segments; the segment holding the
    header of the third PDU is not captured, and a later segment inside a PDU
    body starts like a whole A-ASSOCIATE-RQ (but does not end where its length
    says), followed by zero bytes"""
    pdus = store_pdus(msg_id, bytes(9000))
    data = bytearray(b"".join(pdus))
    hs = headers(pdus)
    bounds = cut(len(data))
    lost = next(i for i, (a, b) in enumerate(bounds) if a < hs[2] < b)
    fake = fake_rq_full(200)
    a = next(a for a, b in bounds[lost + 1:] if all(not (a <= h < a + 206 + 6) for h in hs))
    data[a:a + len(fake)] = fake
    send_stream(c, True, bytes(data), bounds, drop={lost})
    c.send(False, pdata((1, 3, store_rsp(msg_id))))


STORE_CTX = ((1, CT_STORAGE, (IMPLICIT_LE,)),)


def segmenting_benign(out, clock):
    gap = lambda: clock.tick(0.3)  # noqa: E731
    # 1. pynetdicom-like: headers split 3 + 3, 1 + 5 and 5 + 1, pixel words 1, 0, 1
    c = associate(out, clock, "10.77.0.50", 45000, ctxs=STORE_CTX)
    store_with_straddles(c, 1, pixels_101(9000), [(1, 3), (2, 1), (3, 5)])
    release(c)
    gap()

    # 2. DCMTK-like: a 12-byte header split 4 + 8; zero pixels with, at the body
    #    segment starts, data that reads as the PDU headers each rule of the batch
    #    flags (DATA_HEADERS); a body segment not captured
    c = associate(out, clock, "10.77.0.51", 45001, ctxs=STORE_CTX)
    n = 56000
    starts = dcmtk_body_starts(n)
    runs = [(o, DATA_HEADERS[k % len(DATA_HEADERS)]) for k, o in enumerate(starts)]
    send_segments(c, True, dcmtk_segments(store_pdus(1, pixels_zero(n, runs)), split=(2, 4), drop=(3, 1)))
    c.send(False, pdata((1, 3, store_rsp(1))))
    release(c)
    gap()

    # 3. a P-DATA-TF of 20 MiB: 2 MiB into it (18 MiB before its end), data that reads
    #    as a whole A-ASSOCIATE-RQ in a segment of its own, then as a PDU of type 9
    c = associate(out, clock, "10.77.0.52", 45002, ctxs=STORE_CTX)
    c.send(True, pdata((1, 3, store_rq(1))))
    big = 20 << 20
    first = struct.pack(">BBIIBB", 4, 0, big, big - 4, 1, 0)
    first += b"\0" * (MSS - len(first))
    c._pkt(True, "PA", first)
    c.seq[True] += (2 << 20) - MSS
    rq = fake_rq_full(200)
    c._pkt(True, "PA", rq + b"\0" * (206 - len(rq)))
    c._pkt(True, "PA", pdu(9, b"\0" * 4) + b"\0" * 100)
    c._pkt(False, "A")
    c.reset()
    gap()

    # 4. a segment holding a PDU header not captured, then data that starts like a
    #    whole A-ASSOCIATE-RQ
    c = associate(out, clock, "10.77.0.53", 45003, ctxs=STORE_CTX)
    store_lost_header(c, 1)
    release(c)


def segmenting_attacks(out, clock):
    gap = lambda: clock.tick(0.3)  # noqa: E731
    A = "10.66.0.70"

    # 200 after a C-STORE whose headers are split 3 + 3, 1 + 5 and 5 + 1
    c = associate(out, clock, A, 47000, ctxs=STORE_CTX)
    store_with_straddles(c, 1, pixels_101(9000), [(1, 3), (2, 1), (3, 5)])
    c.send(True, pdu(9, b"\0" * 4))
    c.reset()
    gap()

    # 208 + 226 (an A-RELEASE-RQ of length 0) after a DCMTK-like C-STORE with a
    # 12-byte header split 4 + 8 and a body segment not captured
    c = associate(out, clock, A, 47001, ctxs=STORE_CTX)
    n = 10000
    runs = [(o, b"\x01\x00\x00\x00\x01\x00") for o in dcmtk_body_starts(n)]
    send_segments(c, True, dcmtk_segments(store_pdus(1, pixels_zero(n, runs)), split=(2, 4), drop=(3, 1)))
    c.send(False, pdata((1, 3, store_rsp(1))))
    c.send(True, pdu(5, b""))
    c.reset()
    gap()

    # 226: an A-ABORT of length 20 whose header is split 1 + 5, after a C-ECHO-RQ
    c = associate(out, clock, A, 47002)
    rq = pdata((1, 3, echo_rq(1)))
    data = rq + pdu(7, b"\0" * 20)
    send_stream(c, True, data, cut(len(data), [len(rq) + 1]))
    c.reset()
    gap()

    # 200, the segment retransmitted: one alert
    c = associate(out, clock, A, 47003)
    echo(c)
    bad = pdu(9, b"\0" * 4)
    send_stream(c, True, bad, cut(len(bad)), dup={0})
    c.reset()
    gap()

    # 216 after a lost boundary (a segment holding a PDU header not captured, then
    # data that starts like a whole A-ASSOCIATE-RQ), 6 s later an A-ASSOCIATE-RQ in
    # a segment of its own
    c = associate(out, clock, A, 47004, ctxs=STORE_CTX)
    store_lost_header(c, 1)
    clock.tick(6)
    c.send(True, assoc_rq("LABPACS", "LABSCU"))
    c.reset()
    gap()

    # 200 x 12: 12 parallel associations from one client to one SCP port, their
    # C-STOREs interleaved segment by segment, then a PDU of type 9 on each
    conns = [associate(out, clock, "10.66.0.71", 47100 + i, ctxs=STORE_CTX) for i in range(12)]
    streams = []
    for c in conns:
        data = b"".join(store_pdus(1, pixels_101(2400)))
        streams.append((data, cut(len(data))))
    for k in range(max(len(b) for _, b in streams)):
        for c, (data, bounds) in zip(conns, streams):
            if k < len(bounds):
                a, b = bounds[k]
                c._pkt(True, "PA", data[a:b], 0.0002)
    for c in conns:
        c._pkt(False, "A")
        c.send(False, pdata((1, 3, store_rsp(1))))
    for c in conns:
        c.send(True, pdu(9, b"\0" * 4))
    for c in conns:
        c.reset()


def rates(out, clock):
    ctx = ((1, FIND_PATIENT, (IMPLICIT_LE,)),)

    def find(c, i, name, dt):
        c.send(True, pdata((1, 3, find_rq(i))))
        c.send(True, pdata((1, 2, patient_query(name))), dt=dt)
        c.send(False, pdata((1, 3, find_rsp(i, 0x0000))))

    # 223: 12 wildcard queries spread over 30 s (at most 4 in any 10 s): no alert
    c = associate(out, clock, "10.66.1.10", 48000, ctxs=ctx)
    for i in range(12):
        find(c, i + 1, b"%c*" % (65 + i), 2.5)
    release(c)
    clock.tick(1)
    # 223: 10 within 1 s from another source: one alert, on the 10th
    c = associate(out, clock, "10.66.1.11", 48001, ctxs=ctx)
    for i in range(10):
        find(c, i + 1, b"%c*" % (65 + i), 0.05)
    release(c)
    clock.tick(11)

    def assoc(cip, cport, called="LABPACS", calling="MODALITY", dt=0.0001):
        c = Conn(out, clock, cip, cport)
        c._pkt(True, "S", dt=dt)
        c._pkt(False, "SA", dt=0.0001)
        c._pkt(True, "A", dt=0.0001)
        c.send(True, assoc_rq(called, calling), dt=0.0001)
        c.send(False, assoc_ac(called, calling), dt=0.0001)
        c.reset()

    # 220: two sources, 15 A-ASSOCIATE-RQ each within 4 s (30 together): no alert
    for i in range(15):
        assoc("10.66.1.20", 49000 + i, dt=0.13)
        assoc("10.66.1.21", 49100 + i)
    clock.tick(6)
    # 220: one source, 22 within 2 s: alerts on the 21st and the 22nd
    for i in range(22):
        assoc("10.66.1.22", 49200 + i, dt=0.09)
    clock.tick(6)

    # 228: 12 sources of one /16, each with a baseline association, then each with
    # the AE titles swapped: 12 alerts
    srcs = ["10.66.%d.%d" % (2 + i // 4, 10 + i) for i in range(12)]
    for i, s in enumerate(srcs):
        assoc(s, 50000 + i, called="LABPACS", calling="SCU%d" % i, dt=0.05)
    for i, s in enumerate(srcs):
        assoc(s, 50100 + i, called="SCU%d" % i, calling="LABPACS", dt=0.05)


def parallel_sources(out, clock):
    """10 sources of one /16 (their addresses differ only in the last two octets)
    at once: each sends 21 A-ASSOCIATE-RQ within 2 s (rule 220: one alert each, on
    the 21st), then 10 wildcard queries within 1 s (rule 223: one alert each, on
    the 10th). Only the segments that the rules read are sent: each connection's
    A-ASSOCIATE-RQ, and the P-DATA-TF with the query data set."""
    srcs = ["10.66.%d.%d" % (5 + i // 3, 20 + i) for i in range(10)]
    for k in range(21):
        for i, s in enumerate(srcs):
            c = Conn(out, clock, s, 51000 + 100 * i + k)
            c._pkt(True, "PA", assoc_rq("LABPACS", "MODALITY"), dt=0.009)
    clock.tick(6)
    conns = []
    for i, s in enumerate(srcs):
        c = Conn(out, clock, s, 52000 + i)
        c._pkt(True, "PA", assoc_rq("LABPACS", "MODALITY", ctxs=((1, FIND_PATIENT, (IMPLICIT_LE,)),)))
        conns.append(c)
    for k in range(10):
        for c in conns:
            c._pkt(True, "PA", pdata((1, 2, patient_query(b"%c*" % (65 + k)))), dt=0.009)


def main():
    cmd = sys.argv[1]
    out = []
    if cmd == "attacks":
        attacks(out, Clock(1795000000.0))
        wrpcap(sys.argv[2], out)
    elif cmd == "flood":
        flood(out, Clock(1795000000.0))
        wrpcap(sys.argv[2], out)
    elif cmd in ("segmenting-benign", "segmenting-attacks", "rates", "parallel-sources"):
        {"segmenting-benign": segmenting_benign, "segmenting-attacks": segmenting_attacks,
         "rates": rates, "parallel-sources": parallel_sources}[cmd](out, Clock(1795300000.0))
        wrpcap(sys.argv[2], out)
    elif cmd == "merge":
        benign = list(PcapReader(sys.argv[2]))
        atk = list(PcapReader(sys.argv[3]))
        shift = float(benign[-1].time) + 2 - float(atk[0].time)
        for p in atk:
            p.time = float(p.time) + shift
        wrpcap(sys.argv[4], benign + atk)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
