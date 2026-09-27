"""
Captures covering every cleartext authentication protocol.

Mirrors the protocol set an analyst actually meets in credential-exposure
work: FTP, Telnet in both line and character mode, POP3, IMAP with each
SASL mechanism, SMTP AUTH, and HTTP Basic, Digest and NTLM.
"""
import base64, hashlib, os, socket, struct

pkts = []
t = 1700700000
A, B = '001122334455', '66778899aabb'


def eth(d, s, et, p): return bytes.fromhex(d) + bytes.fromhex(s) + struct.pack('!H', et) + p
def ip4(s, d, proto, p):
    return (struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(p), 1, 0x4000, 64, proto, 0)
            + socket.inet_aton(s) + socket.inet_aton(d) + p)
def tcp(sp, dp, flags, p=b'', seq=1):
    return struct.pack('!HHIIBBHHH', sp, dp, seq, 0, 5 << 4, flags, 8192, 0, 0) + p


def session(client, server, cport, sport, exchanges, start):
    """exchanges: list of (direction, bytes) where direction is 'c' or 's'."""
    global t
    cseq = sseq = 1
    pkts.append((start, eth(A, B, 0x0800, ip4(client, server, 6, tcp(cport, sport, 0x02)))))
    pkts.append((start + .01, eth(B, A, 0x0800, ip4(server, client, 6, tcp(sport, cport, 0x12)))))
    for i, (direction, data) in enumerate(exchanges):
        ts = start + 0.1 + i * 0.05
        if direction == 'c':
            pkts.append((ts, eth(A, B, 0x0800, ip4(client, server, 6, tcp(cport, sport, 0x18, data, cseq)))))
            cseq += len(data)
        else:
            pkts.append((ts, eth(B, A, 0x0800, ip4(server, client, 6, tcp(sport, cport, 0x18, data, sseq)))))
            sseq += len(data)


b64 = lambda x: base64.b64encode(x).decode()

# --- FTP ---
session('10.0.1.10', '10.0.1.50', 40001, 21, [
    ('s', b'220 ProFTPD Server ready\r\n'),
    ('c', b'USER anonymous\r\n'), ('s', b'331 Password required\r\n'),
    ('c', b'PASS Password123!\r\n'), ('s', b'230 User logged in\r\n'),
], t)

# --- Telnet, line mode ---
session('10.0.1.11', '10.0.1.51', 40002, 23, [
    ('s', b'\xff\xfd\x18\xff\xfd \xff\xfd#\xff\xfd\'Ubuntu 22.04\r\nlogin: '),
    ('c', b'\xff\xfb\x18\xff\xfb\x1fadmin\r\n'),
    ('s', b'Password: '),
    ('c', b'Sup3rSecret\r\n'),
    ('s', b'\r\nWelcome to Ubuntu\r\n$ '),
], t + 20)

# --- Telnet, character mode: one keystroke per packet, server echoes ---
ex = [('s', b'\xff\xfb\x01\xff\xfb\x03login: ')]
for ch in b'operator':
    ex.append(('c', bytes([ch]))); ex.append(('s', bytes([ch])))
ex.append(('c', b'\r\n')); ex.append(('s', b'\r\nPassword: '))
for ch in b'Tr0ub4dor':
    ex.append(('c', bytes([ch])))       # password is not echoed
ex.append(('c', b'\r\n')); ex.append(('s', b'\r\n$ '))
session('10.0.1.12', '10.0.1.52', 40003, 23, ex, t + 40)

# --- POP3 USER/PASS ---
session('10.0.1.13', '10.0.1.53', 40004, 110, [
    ('s', b'+OK POP3 server ready <1896.697@mail>\r\n'),
    ('c', b'USER mailuser\r\n'), ('s', b'+OK\r\n'),
    ('c', b'PASS letmein2024\r\n'), ('s', b'+OK Logged in\r\n'),
], t + 60)

# --- POP3 APOP ---
digest = hashlib.md5(b'<1896.697@mail>secretpw').hexdigest()
session('10.0.1.14', '10.0.1.53', 40005, 110, [
    ('s', b'+OK POP3 ready <1896.697@mail>\r\n'),
    ('c', f'APOP apopuser {digest}\r\n'.encode()), ('s', b'+OK\r\n'),
], t + 70)

# --- IMAP LOGIN plaintext ---
session('10.0.1.15', '10.0.1.54', 40006, 143, [
    ('s', b'* OK IMAP4rev1 ready\r\n'),
    ('c', b'a001 LOGIN alice@corp.local Winter2024!\r\n'),
    ('s', b'a001 OK LOGIN completed\r\n'),
], t + 80)

# --- IMAP AUTHENTICATE PLAIN ---
session('10.0.1.16', '10.0.1.54', 40007, 143, [
    ('s', b'* OK IMAP4rev1 ready\r\n'),
    ('c', b'a001 AUTHENTICATE PLAIN\r\n'), ('s', b'+ \r\n'),
    ('c', b64(b'\x00bob@corp.local\x00Passw0rd!').encode() + b'\r\n'),
    ('s', b'a001 OK\r\n'),
], t + 90)

# --- IMAP AUTHENTICATE CRAM-MD5 ---
chal = b64(b'<12345.67890@imap.corp.local>')
resp = b64(b'carol 8a9f2b1c3d4e5f6071829304a5b6c7d8')
session('10.0.1.17', '10.0.1.54', 40008, 143, [
    ('s', b'* OK ready\r\n'),
    ('c', b'a001 AUTHENTICATE CRAM-MD5\r\n'),
    ('s', b'+ ' + chal.encode() + b'\r\n'),
    ('c', resp.encode() + b'\r\n'), ('s', b'a001 OK\r\n'),
], t + 100)

# --- IMAP AUTHENTICATE DIGEST-MD5 ---
dresp = b64(b'username="dave",realm="corp.local",nonce="abc123",'
            b'response=6629fae49393a05397450978507c4ef1')
session('10.0.1.18', '10.0.1.54', 40009, 143, [
    ('s', b'* OK ready\r\n'),
    ('c', b'a001 AUTHENTICATE DIGEST-MD5\r\n'),
    ('s', b'+ ' + b64(b'realm="corp.local",nonce="abc123"').encode() + b'\r\n'),
    ('c', dresp.encode() + b'\r\n'), ('s', b'a001 OK\r\n'),
], t + 110)

# --- IMAP AUTHENTICATE XYMPKI (vendor mechanism) ---
session('10.0.1.19', '10.0.1.54', 40010, 143, [
    ('s', b'* OK ready\r\n'),
    ('c', b'a001 AUTHENTICATE XYMPKI\r\n'), ('s', b'+ \r\n'),
    ('c', b64(b'\x00vendor-token-blob\x00').encode() + b'\r\n'),
    ('s', b'a001 OK\r\n'),
], t + 120)

# --- SMTP AUTH PLAIN ---
session('10.0.1.20', '10.0.1.55', 40011, 25, [
    ('s', b'220 mail.corp.local ESMTP\r\n'),
    ('c', b'EHLO client\r\n'), ('s', b'250-AUTH PLAIN LOGIN CRAM-MD5\r\n250 OK\r\n'),
    ('c', b'AUTH PLAIN ' + b64(b'\x00smtpuser\x00MailPass99').encode() + b'\r\n'),
    ('s', b'235 Authentication successful\r\n'),
], t + 130)

# --- SMTP AUTH LOGIN ---
session('10.0.1.21', '10.0.1.55', 40012, 25, [
    ('s', b'220 ESMTP\r\n'), ('c', b'EHLO client\r\n'), ('s', b'250 AUTH LOGIN\r\n'),
    ('c', b'AUTH LOGIN\r\n'), ('s', b'334 ' + b64(b'Username:').encode() + b'\r\n'),
    ('c', b64(b'erin@corp.local').encode() + b'\r\n'),
    ('s', b'334 ' + b64(b'Password:').encode() + b'\r\n'),
    ('c', b64(b'Sm7pL0gin!').encode() + b'\r\n'),
    ('s', b'235 OK\r\n'),
], t + 140)

# --- SMTP AUTH CRAM-MD5 ---
session('10.0.1.22', '10.0.1.55', 40013, 25, [
    ('s', b'220 ESMTP\r\n'), ('c', b'AUTH CRAM-MD5\r\n'),
    ('s', b'334 ' + b64(b'<99887.11223@mail>').encode() + b'\r\n'),
    ('c', b64(b'frank fedcba9876543210fedcba9876543210').encode() + b'\r\n'),
    ('s', b'235 OK\r\n'),
], t + 150)

# --- HTTP Basic ---
session('10.0.1.23', '10.0.1.56', 40014, 80, [
    ('c', b'GET /admin/ HTTP/1.1\r\nHost: intranet.corp.local\r\n\r\n'),
    ('s', b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Admin"\r\nContent-Length: 0\r\n\r\n'),
    ('c', b'GET /admin/ HTTP/1.1\r\nHost: intranet.corp.local\r\nAuthorization: Basic '
          + b64(b'webadmin:Adm1nP@ss').encode() + b'\r\n\r\n'),
    ('s', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'),
], t + 160)

# --- HTTP Digest ---
session('10.0.1.24', '10.0.1.56', 40015, 80, [
    ('c', b'GET /secure/ HTTP/1.1\r\nHost: intranet.corp.local\r\n\r\n'),
    ('s', b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm="Secure Area", '
          b'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth"\r\nContent-Length: 0\r\n\r\n'),
    ('c', b'GET /secure/ HTTP/1.1\r\nHost: intranet.corp.local\r\n'
          b'Authorization: Digest username="digestuser", realm="Secure Area", '
          b'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/secure/", '
          b'response="6629fae49393a05397450978507c4ef1", qop=auth, nc=00000001, '
          b'cnonce="0a4f113b"\r\n\r\n'),
    ('s', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'),
], t + 170)

# --- HTTP NTLM (v1 authenticate message) ---
def ntlm_type3(user, domain, ws, nt_len=24):
    lm, nt = b'\x00' * 24, b'\xbb' * nt_len
    du, uu, wu = domain.encode('utf-16-le'), user.encode('utf-16-le'), ws.encode('utf-16-le')
    cur = 64
    def f(d):
        nonlocal cur
        r = struct.pack('<HHI', len(d), len(d), cur); cur += len(d); return r
    hdr = (b'NTLMSSP\x00' + struct.pack('<I', 3) + f(lm) + f(nt) + f(du) + f(uu)
           + f(wu) + struct.pack('<HHI', 0, 0, cur) + struct.pack('<I', 0))
    return hdr.ljust(64, b'\x00') + lm + nt + du + uu + wu

session('10.0.1.25', '10.0.1.56', 40016, 80, [
    ('c', b'GET /win/ HTTP/1.1\r\nHost: intranet.corp.local\r\n\r\n'),
    ('s', b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n'),
    ('c', b'GET /win/ HTTP/1.1\r\nHost: intranet.corp.local\r\nAuthorization: NTLM '
          + base64.b64encode(ntlm_type3('ntlmuser', 'CORP', 'WKSTN-07')) + b'\r\n\r\n'),
    ('s', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'),
], t + 180)

pkts.sort(key=lambda x: x[0])
out = '/tmp/credentials.pcapng'
with open(out, 'wb') as f:
    f.write(struct.pack('<IIIHHq', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack('<I', 28))
    f.write(struct.pack('<III', 0x00000001, 20, 1) + struct.pack('<I', 65535) + struct.pack('<I', 20))
    for ts, data in pkts:
        pad = (-len(data)) % 4; us = int(ts * 1_000_000); blen = 32 + len(data) + pad
        f.write(struct.pack('<IIIIIII', 0x00000006, blen, 0, us >> 32, us & 0xffffffff, len(data), len(data)))
        f.write(data + b'\x00' * pad); f.write(struct.pack('<I', blen))
print(f'credential fixture: {len(pkts)} packets -> {out}')
