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

Every PDU is sent in one TCP segment that starts with its PDU header, which
is what mmt-dpi needs to extract dicom.* attributes.
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


def main():
    cmd = sys.argv[1]
    out = []
    if cmd == "attacks":
        attacks(out, Clock(1795000000.0))
        wrpcap(sys.argv[2], out)
    elif cmd == "flood":
        flood(out, Clock(1795000000.0))
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
