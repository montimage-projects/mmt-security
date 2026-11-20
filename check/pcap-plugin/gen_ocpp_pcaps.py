#!/usr/bin/env python3
"""Write the synthetic OCPP 1.6-J captures of check/pcap-plugin/pcap/.

They exercise rules 230 (rules/properties_all/230.ocpp_heartbeat_flood.xml) and
231 (rules/properties_all/231.ocpp_charging_limit.xml), which need the OCPP
plugin `ocpp_example` of mmt-plugin-generator (doc/rule.md, section 7).

Each charge point (CP) session is one TCP connection to the central system
(CS) 10.0.0.1:9000: the three-way handshake, the WebSocket opening handshake
offering and selecting the `ocpp1.6` subprotocol (OCPP-J 1.6 section 3.1.2),
then OCPP-J messages in WebSocket text frames (masked from the CP, unmasked
from the CS, RFC 6455), every CALL answered by its CALLRESULT, and a FIN
exchange. The output is deterministic (fixed timestamps, addresses and masks):
running this script again rewrites the same bytes.

    python3 check/pcap-plugin/gen_ocpp_pcaps.py [output dir]

The default output dir is check/pcap-plugin/pcap next to this script. Needs
scapy (Ubuntu: python3-scapy).
"""

import os
import random
import sys

from scapy.all import IP, TCP, Ether, Raw, wrpcap

T0 = 1700000000  # 2023-11-14T22:13:20Z, the capture's time origin (whole second)
CS_IP = "10.0.0.1"
CS_PORT = 9000
CS_MAC = "02:00:00:00:00:01"
CP_MAC = "02:00:00:00:00:02"
REPLY_DELAY = 0.02  # the CS answers a CP's CALL (and the CP the CS's) after 20 ms


def ws_frame(payload, masked, rng):
    """One unfragmented WebSocket text frame (FIN, opcode 1)."""
    data = payload.encode()
    n = len(data)
    hdr = bytes([0x81])
    mask_bit = 0x80 if masked else 0
    if n < 126:
        hdr += bytes([mask_bit | n])
    else:
        hdr += bytes([mask_bit | 126, n >> 8, n & 0xFF])
    if not masked:
        return hdr + data
    key = bytes(rng.randrange(256) for _ in range(4))
    return hdr + key + bytes(b ^ key[i % 4] for i, b in enumerate(data))


class Session:
    """One CP <-> CS TCP connection; collects (time, packet) pairs."""

    def __init__(self, cp_ip, cp_port, start, seed):
        self.cp_ip, self.cp_port = cp_ip, cp_port
        self.rng = random.Random(seed)
        self.seq = {"cp": 1000 + seed * 7919, "cs": 5000 + seed * 104729}
        self.pkts = []
        self.ids = 0
        self._tcp("cp", start, "S")
        self.seq["cp"] += 1
        self._tcp("cs", start + 0.001, "SA")
        self.seq["cs"] += 1
        self._tcp("cp", start + 0.002, "A")
        self._data("cp", start + 0.003, (
            "GET /ocpp/CP%d HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Protocol: ocpp1.6\r\nSec-WebSocket-Version: 13\r\n\r\n"
            % (cp_port, CS_IP, CS_PORT)).encode())
        self._data("cs", start + 0.004, (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
            "Sec-WebSocket-Protocol: ocpp1.6\r\n\r\n").encode())

    def _tcp(self, side, t, flags, payload=b""):
        other = "cs" if side == "cp" else "cp"
        ack = self.seq[other] if "A" in flags else 0
        if side == "cp":
            l2 = Ether(src=CP_MAC, dst=CS_MAC)
            l3 = IP(src=self.cp_ip, dst=CS_IP)
            l4 = TCP(sport=self.cp_port, dport=CS_PORT)
        else:
            l2 = Ether(src=CS_MAC, dst=CP_MAC)
            l3 = IP(src=CS_IP, dst=self.cp_ip)
            l4 = TCP(sport=CS_PORT, dport=self.cp_port)
        l4.flags, l4.seq, l4.ack, l4.window = flags, self.seq[side], ack, 64240
        pkt = l2 / l3 / l4
        if payload:
            pkt = pkt / Raw(payload)
        pkt = Ether(bytes(pkt))  # fix lengths and checksums
        pkt.time = t
        self.pkts.append((t, pkt))
        self.seq[side] += len(payload)

    def _data(self, side, t, payload):
        self._tcp(side, t, "PA", payload)

    def _msg(self, side, t, text):
        self._data(side, t, ws_frame(text, side == "cp", self.rng))

    def call(self, side, t, action, payload, result='{"status":"Accepted"}'):
        """A CALL from `side` at `t` and its CALLRESULT from the other side."""
        self.ids += 1
        uid = "%d-%d" % (self.cp_port, self.ids)
        self._msg(side, t, '[2,"%s","%s",%s]' % (uid, action, payload))
        other = "cs" if side == "cp" else "cp"
        self._msg(other, t + REPLY_DELAY, '[3,"%s",%s]' % (uid, result))

    def heartbeat(self, t):
        self.call("cp", t, "Heartbeat", "{}", '{"currentTime":"2023-11-14T22:13:20Z"}')

    def charging_profile(self, t, limit, unit):
        self.call("cs", t, "SetChargingProfile", (
            '{"connectorId":1,"csChargingProfiles":{"chargingProfileId":%d,'
            '"stackLevel":0,"chargingProfilePurpose":"TxDefaultProfile",'
            '"chargingProfileKind":"Absolute","chargingSchedule":{'
            '"chargingRateUnit":"%s","chargingSchedulePeriod":['
            '{"startPeriod":0,"limit":%s}]}}}' % (self.ids + 1, unit, limit)))

    def close(self, t):
        self._tcp("cp", t, "FA")
        self.seq["cp"] += 1
        self._tcp("cs", t + 0.001, "FA")
        self.seq["cs"] += 1
        self._tcp("cp", t + 0.002, "A")


def write(path, sessions):
    pkts = sorted((p for s in sessions for p in s.pkts), key=lambda tp: tp[0])
    wrpcap(path, [p for _, p in pkts])
    print("%s: %d packets, %d bytes" % (path, len(pkts), os.path.getsize(path)))


def heartbeat_flood(path):
    """Rule 230 at the defaults (more than 10 Heartbeats in 10 s, per session):
    CP A, 30 Heartbeats every 250 ms: 1 alert (its 11th Heartbeat);
    CP B, 60 Heartbeats every 250 ms (15 s, two windows): 2 alerts;
    CP C, 5 Heartbeats every 60 s: no alert."""
    a = Session("10.0.0.11", 50001, T0 + 1.0, 1)
    b = Session("10.0.0.12", 50002, T0 + 1.1, 2)
    c = Session("10.0.0.13", 50003, T0 + 1.2, 3)
    for i in range(30):
        a.heartbeat(T0 + 1.5 + 0.25 * i)
    for i in range(60):
        b.heartbeat(T0 + 1.6 + 0.25 * i)
    for i in range(5):
        c.heartbeat(T0 + 1.7 + 60 * i)
    a.close(T0 + 10)
    b.close(T0 + 20)
    c.close(T0 + 250)
    write(path, [a, b, c])


def charging_limit(path):
    """Rule 231 at the defaults (above 32 A or 22000 W): SetChargingProfile
    from the CS at 10, 90, 32, 32.1 and 16 A and at 22000 and 30000 W, each
    answered: 3 alerts (90 A, 32.1 A, 30000 W)."""
    s = Session("10.0.0.21", 50010, T0 + 1.0, 4)
    s.call("cp", T0 + 1.5, "BootNotification",
           '{"chargePointVendor":"Example","chargePointModel":"AC22"}',
           '{"status":"Accepted","currentTime":"2023-11-14T22:13:21Z","interval":60}')
    t = T0 + 3
    for limit, unit in (("10.0", "A"), ("90.0", "A"), ("32.0", "A"), ("32.1", "A"),
                        ("16.0", "A"), ("22000.0", "W"), ("30000.0", "W")):
        s.charging_profile(t, limit, unit)
        t += 2
    s.close(t)
    write(path, [s])


def benign(path):
    """No alert at the defaults:
    a normal CP over 10 min (BootNotification, Authorize, StatusNotification,
    a Heartbeat every 60 s, SetChargingProfile at 0, 10, 16 and 32 A and at
    11000 and 22000 W); a CP sending exactly 10 Heartbeats in 2.25 s; a CP
    sending 1 Heartbeat per second for 20 s."""
    n = Session("10.0.0.31", 50020, T0 + 1.0, 5)
    n.call("cp", T0 + 1.5, "BootNotification",
           '{"chargePointVendor":"Example","chargePointModel":"AC22"}',
           '{"status":"Accepted","currentTime":"2023-11-14T22:13:21Z","interval":60}')
    n.call("cp", T0 + 2.5, "StatusNotification",
           '{"connectorId":1,"errorCode":"NoError","status":"Available"}', "{}")
    n.call("cp", T0 + 30.5, "Authorize", '{"idTag":"TAG0001"}',
           '{"idTagInfo":{"status":"Accepted"}}')
    profiles = (("0.0", "A"), ("10.0", "A"), ("16.0", "A"), ("32.0", "A"),
                ("11000.0", "W"), ("22000.0", "W"))
    # a session's packets are emitted in time order (its TCP sequence numbers)
    events = [(T0 + 40.5 + 90 * i, n.charging_profile, (limit, unit))
              for i, (limit, unit) in enumerate(profiles)]
    events += [(T0 + 61.5 + 60 * i, n.heartbeat, ()) for i in range(10)]
    for t, fn, args in sorted(events, key=lambda e: e[0]):
        fn(t, *args)
    n.close(T0 + 620)
    d = Session("10.0.0.32", 50021, T0 + 100.0, 6)
    for i in range(10):
        d.heartbeat(T0 + 100.5 + 0.25 * i)
    d.close(T0 + 110)
    e = Session("10.0.0.33", 50022, T0 + 200.0, 7)
    for i in range(20):
        e.heartbeat(T0 + 200.5 + 1.0 * i)
    e.close(T0 + 225)
    write(path, [n, d, e])


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "pcap")
    os.makedirs(out, exist_ok=True)
    heartbeat_flood(os.path.join(out, "ocpp_230_heartbeat_flood.pcap"))
    charging_limit(os.path.join(out, "ocpp_231_charging_limit.pcap"))
    benign(os.path.join(out, "ocpp_benign.pcap"))


if __name__ == "__main__":
    main()
